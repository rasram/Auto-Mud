const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');

function application(topology) {
  const context = vm.createContext({Intl, Date});
  vm.runInContext(source.slice(0, source.lastIndexOf("$$('.nav-item')")), context);
  vm.runInContext(`state.data = ${JSON.stringify({topology})}`, context);
  return expression => JSON.parse(JSON.stringify(vm.runInContext(expression, context)));
}

test('permission filters see retained unknown traffic beyond the display limit', () => {
  const edges = Array.from({length:130}, (_, index) => ({
    source:`device-${index}`, target:'target', count:2, permissions:{denied:2}, proto:'tcp', port:22,
  }));
  edges.push({source:'external:10.0.0.250', target:'external:ff02::1', count:3, permissions:{unknown_device:3}});
  const app = application({nodes:[], edges});
  assert.equal(app("normalizedTopology('all').edges.length"), 36);
  const unknown = app("normalizedTopology('unknown')");
  assert.equal(unknown.totalMatching, 1);
  assert.equal(unknown.totalFlows, 3);
  assert.equal(unknown.edges[0].kind, 'unknown');
  assert.equal(unknown.edges[0].endpoints.length, 1);
});

test('mixed relationships match each relevant permission filter explicitly', () => {
  const app = application({nodes:[], edges:[
    {source:'a', target:'b', count:3, permissions:{allowed:1, denied:1, unknown_policy:1}},
  ]});
  for (const permission of ['all','allowed','denied','unknown','mixed']) {
    const result = app(`normalizedTopology('${permission}')`);
    assert.equal(result.totalMatching, 1);
    assert.equal(result.edges[0].kind, 'mixed');
  }
});

test('single-permission allowed and denied relationships stay separate', () => {
  const app = application({nodes:[], edges:[
    {source:'a', target:'b', count:1, permissions:{allowed:1}},
    {source:'a', target:'b', count:2, permissions:{denied:2}},
  ]});
  assert.equal(app("normalizedTopology('all').totalMatching"), 2);
  assert.equal(app("normalizedTopology('allowed').totalFlows"), 1);
  assert.equal(app("normalizedTopology('denied').totalFlows"), 2);
  assert.equal(app("normalizedTopology('unknown').totalMatching"), 0);
});

test('an available incomplete GNN response is displayed as incomplete', () => {
  const app = application({nodes:[], edges:[]});
  assert.equal(app("gnnState({gnn:'available',gnn_detail:{complete:false},sensor:'unhealthy'})"), 'incomplete');
  assert.equal(app("gnnState({gnn:'available',gnn_detail:{complete:true},sensor:'unhealthy'})"), 'unhealthy');
  assert.equal(app("gnnState({gnn:'available',gnn_detail:{complete:true},sensor:'healthy',gnn_fresh:false})"), 'stale');
});

test('fifteen prior windows alone never claim full warm-up', () => {
  const app = application({nodes:[], edges:[]});
  assert.match(app("warmupLabel({history_state:{prior_windows:15,observed_age_seconds:900,fully_warmed:false}})"), /15 \/ 60 observed minutes/);
  assert.equal(app("warmupLabel({history_state:{prior_windows:15,observed_age_seconds:3600,fully_warmed:true}})"), 'History fully warmed');
});
