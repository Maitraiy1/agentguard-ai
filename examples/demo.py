"""Safe local integration demo. No network calls or external side effects."""
from pathlib import Path
from tempfile import TemporaryDirectory

from agentguard import Action, ApprovalError, Decision, Engine, Policy, Rule


def main():
    policy = Policy((Rule("notes.publish", "notes/demo", "demo-agent", Decision.APPROVAL),))
    action = Action("notes.publish", "notes/demo", "demo-agent", {"text": "Hello!"})
    with TemporaryDirectory() as directory:
        engine = Engine(Path(directory) / "state.sqlite3", policy, reviewers={"operator"})
        request_id = engine.request(action)
        print("Review this exact request:", engine.inspect(request_id))
        # Demo only: production must obtain this identity from trusted authentication.
        engine.review(request_id, reviewer="operator", approve=True)
        result = engine.execute(action, lambda approved: approved.parameters["text"],
                                request_id=request_id)
        print("Guarded handler result:", result)
        try:
            engine.execute(action, lambda _: None, request_id=request_id)
        except ApprovalError as error:
            print("Replay blocked:", error)


if __name__ == "__main__":
    main()
