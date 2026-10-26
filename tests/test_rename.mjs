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

// The poll can land before the rename's response: its restored title stands.
test("a poll that already has the new name keeps its title", () => {
  const panes = fleet(), sheet = { ...panes[0] };
  Object.assign(panes[0], { name: "", title: "Agent's" });  // the poll, ahead of the POST
  applyRename(panes, sheet, { name: "" });
  assert.equal(panes[0].title, "Agent's");
});

// Responses out of order: an older save landing after a newer name arrived leaves the newer one.
test("a late rename doesn't overwrite a newer name", () => {
  const panes = fleet(), first = { ...panes[1] };  // the sheet showed "" and saved "Old"
  Object.assign(panes[1], { name: "Newer", title: "Newer" });  // a later save, already polled
  applyRename(panes, first, { name: "Old" });
  assert.equal(panes[1].name, "Newer");
  assert.equal(panes[1].title, "Newer");
});

// The response lands after a poll showed a new pane under the same %N: that pane is left alone.
test("a late rename leaves a replacement pane alone", () => {
  const panes = fleet(), sheet = { ...panes[0], birth: "1" };
  Object.assign(panes[0], { birth: "2" });  // the replacement, with the old one's name
  applyRename(panes, sheet, { name: "Gone", session: "moved" });
  assert.equal(panes[0].name, "Mine");
  assert.deepEqual(panes.map((p) => p.session), ["old", "old", "other"]);
});
