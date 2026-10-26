import assert from "node:assert/strict";
import { test } from "node:test";
import { applyRename } from "../web/m/pane-model.js";

const fleet = () => [
  { pane_id: "%1", session: "old", name: "Mine", title: "Mine" },
  { pane_id: "%2", session: "old", name: "", title: "Agent's" },
  { pane_id: "%3", session: "other", name: "", title: "Else" },
];

// The sheet's pane is the listed object itself: every sibling still moves with it.
test("a session rename moves every pane in it, the renamed one first", () => {
  const panes = fleet();
  applyRename(panes, panes[0], { session: "new" });
  assert.deepEqual(panes.map((p) => p.session), ["new", "new", "other"]);
});

// A cleared name drops the old override; the next poll brings the app's own title.
test("clearing a name drops it from the title", () => {
  const panes = fleet();
  applyRename(panes, panes[0], { name: "" });
  assert.equal(panes[0].name, "");
  assert.equal(panes[0].title, null);
  applyRename(panes, panes[1], { name: "Ship it" });
  assert.equal(panes[1].title, "Ship it");
});
