"""Tes v0.16.0: AI Pentesting Agent (agent.py)."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class FakeLLM:
    available = True
    model = "fake"
    base_url = "https://fake"
    api_key = "x"

    def __init__(self, plan_steps=None, verdict=None):
        self.plan_steps = plan_steps or [
            {"action": "recon", "description": "recon", "params": {}},
            {"action": "scan", "description": "scan", "params": {}},
        ]
        self.verdict = verdict or {"verdict": "partial", "reason": "ok",
                                   "next_action": "done"}

    def json_chat(self, messages, **kw):
        # urutan pemanggilan: plan dulu, lalu evaluate per step
        if "steps" in messages[1]["content"] or len(messages) < 2:
            pass
        if "Goal:" in messages[-1]["content"]:
            return {"steps": self.plan_steps}
        return self.verdict

    def chat(self, messages, **kw):
        return json.dumps({"steps": self.plan_steps})


def _executor_factory(findings=None):
    def _run(action, target, params):
        fnds = findings or []
        if action == "scan" and fnds:
            return {"ok": True, "exit_code": 1, "findings": fnds,
                    "command": f"keris {action}"}
        if action == "recon":
            return {"ok": True, "exit_code": 0, "findings": [],
                    "command": f"keris {action}"}
        return {"ok": True, "exit_code": 0, "findings": [], "command": f"keris {action}"}
    return _run


class TestLLMClient:
    def test_not_available_without_key(self):
        import keris.agent as ag

        llm = ag.LLMClient(api_key="")
        assert not llm.available

    def test_available_with_key(self):
        import keris.agent as ag

        llm = ag.LLMClient(api_key="test")
        assert llm.available

    def test_chat_requires_key(self):
        import keris.agent as ag

        llm = ag.LLMClient(api_key="")
        try:
            llm.chat([{"role": "user", "content": "hi"}])
            assert False, "harus raise"
        except RuntimeError:
            pass


class TestParseJson:
    def test_plain_json(self):
        from keris.agent import _parse_json

        assert _parse_json('{"a": 1}') == {"a": 1}

    def test_fenced_json(self):
        from keris.agent import _parse_json

        assert _parse_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_invalid_returns_empty(self):
        from keris.agent import _parse_json

        assert _parse_json("not json") == {}


class TestPlanner:
    def test_rule_plan(self):
        from keris.agent import Planner

        pl = Planner(llm=FakeLLM())
        steps = pl._plan_rule("ambil alih server", "http://x/")
        assert steps
        assert all(s["action"] for s in steps)
        actions = [s["action"] for s in steps]
        assert "recon" in actions and "scan" in actions

    def test_rule_plan_goal_keywords(self):
        from keris.agent import Planner

        pl = Planner(llm=FakeLLM())
        steps = pl._plan_rule("dapatkan shell dan pivot", "http://x/")
        actions = [s["action"] for s in steps]
        assert "shell" in actions and "pivot" in actions

    def test_llm_plan(self):
        from keris.agent import Planner

        pl = Planner(llm=FakeLLM())
        steps = pl.plan("goal", "http://x/")
        assert steps and steps[0]["action"] == "recon"

    def test_llm_plan_unknown_action_filtered(self):
        from keris.agent import Planner

        llm = FakeLLM(plan_steps=[{"action": "bogus", "description": "x"}])
        pl = Planner(llm=llm)
        steps = pl.plan("goal", "http://x/")
        # action tidak valid -> fallback rule-based
        assert steps and steps[0]["action"] in ("recon",)


class TestRunner:
    def test_build_command(self):
        from keris.agent import build_command

        cmd = build_command("recon", "http://x/", {"timeout": 5}, authorized=True)
        assert os.path.basename(cmd[0]).startswith("python")
        assert "-m" in cmd and "keris" in cmd
        assert "recon" in cmd and "http://x/" in cmd
        assert "--authorized" in cmd

    def test_runner_custom_executor(self):
        from keris.agent import AgentRunner

        calls = []

        def ex(action, target, params):
            calls.append((action, target, params))
            return {"ok": True, "findings": []}

        r = AgentRunner(executor=ex)
        res = r.run("recon", "http://x/", {})
        assert res["ok"] and calls


class TestEvaluator:
    def test_success_on_critical(self):
        from keris.agent import Evaluator

        ev = Evaluator(llm=FakeLLM())
        r = ev._evaluate_rule({}, {"ok": True, "findings": [
            {"severity": "CRITICAL", "title": "RCE"}]})
        assert r["verdict"] == "success"

    def test_partial_on_low(self):
        from keris.agent import Evaluator

        ev = Evaluator(llm=FakeLLM())
        r = ev._evaluate_rule({}, {"ok": True, "findings": [
            {"severity": "LOW", "title": "x"}]})
        assert r["verdict"] == "partial"

    def test_failed_no_findings(self):
        from keris.agent import Evaluator

        ev = Evaluator(llm=FakeLLM())
        r = ev._evaluate_rule({}, {"ok": True, "findings": []})
        assert r["verdict"] == "failed"

    def test_llm_evaluate(self):
        from keris.agent import Evaluator

        ev = Evaluator(llm=FakeLLM())
        r = ev.evaluate({"action": "scan"}, {"ok": True, "findings": []}, "goal")
        assert r["verdict"] in ("success", "partial", "failed")


class TestState:
    def test_save_load(self, tmp_path):
        from keris.agent import AgentState

        p = str(tmp_path / "state.json")
        st = AgentState(p)
        st.data["goal"] = "test"
        st.save()
        st2 = AgentState(p).load()
        assert st2.data["goal"] == "test"

    def test_load_missing(self, tmp_path):
        from keris.agent import AgentState

        st = AgentState(str(tmp_path / "none.json")).load()
        assert st.data["goal"] == ""

    def test_clear(self, tmp_path):
        from keris.agent import AgentState

        p = str(tmp_path / "s.json")
        AgentState(p).save()
        st = AgentState(p)
        st.clear()
        assert not os.path.exists(p)


class TestAgent:
    def test_full_run(self, tmp_path):
        import keris.agent as ag

        state_path = str(tmp_path / "state.json")
        report_path = str(tmp_path / "report.md")
        llm = FakeLLM(plan_steps=[
            {"action": "recon", "description": "r", "params": {}},
            {"action": "scan", "description": "s", "params": {}},
        ])
        runner = ag.AgentRunner(executor=_executor_factory(findings=[
            {"severity": "CRITICAL", "title": "SQLi", "endpoint": "http://x/"}]))
        agent = ag.Agent("get shell", "http://x/", max_steps=5, verbose=True,
                         llm=llm, runner=runner,
                         state=ag.AgentState(state_path))
        s = agent.run()
        assert s["steps_executed"] >= 1
        assert s["total_findings"] == 1
        assert os.path.exists(state_path)
        rp = agent.write_report(report_path)
        assert os.path.exists(rp)
        with open(rp, "r", encoding="utf-8") as f:
            content = f.read()
        assert "# Agent Report" in content
        assert "scan" in content

    def test_resume_skips_done(self, tmp_path):
        import keris.agent as ag

        state_path = str(tmp_path / "state.json")
        llm = FakeLLM(plan_steps=[
            {"action": "recon", "description": "r", "params": {}}])
        runner = ag.AgentRunner(executor=_executor_factory())
        agent = ag.Agent("goal", "http://x/", llm=llm, runner=runner,
                         state=ag.AgentState(state_path))
        agent.run()
        # run kedua: langkah sudah terekam di state -> tidak dieksekusi lagi
        agent2 = ag.Agent("goal", "http://x/", llm=llm, runner=runner,
                          state=ag.AgentState(state_path).load())
        s2 = agent2.run()
        assert s2["steps_executed"] >= 1

    def test_max_steps_limits(self, tmp_path):
        import keris.agent as ag

        llm = FakeLLM(plan_steps=[
            {"action": "recon", "description": "r", "params": {}},
            {"action": "scan", "description": "s", "params": {}},
            {"action": "hunt", "description": "h", "params": {}},
        ])
        runner = ag.AgentRunner(executor=_executor_factory())
        agent = ag.Agent("goal", "http://x/", max_steps=1, llm=llm,
                         runner=runner, state=ag.AgentState(str(tmp_path / "s.json")))
        s = agent.run()
        assert s["steps_executed"] == 1

    def test_unauthorized_warns(self, tmp_path):
        import keris.agent as ag

        llm = FakeLLM(plan_steps=[
            {"action": "recon", "description": "r", "params": {}}])
        runner = ag.AgentRunner(executor=_executor_factory())
        agent = ag.Agent("goal", "http://x/", authorized=False, llm=llm,
                         runner=runner, state=ag.AgentState(str(tmp_path / "s.json")))
        s = agent.run()
        assert "recon" in s["results"]


class TestRunAgent:
    def test_run_agent_default(self, tmp_path):
        import keris.agent as ag

        state_path = str(tmp_path / "state.json")
        report_path = str(tmp_path / "report.md")
        s = ag.run_agent("test goal", "http://x/", max_steps=3,
                         executor=_executor_factory(),
                         state_file=state_path, report_file=report_path)
        assert "goal" in s
        assert os.path.exists(report_path)