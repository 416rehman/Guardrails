// The gh commands the kit's workflow scripts give their publishers when every finding quotes a
// kit record, and the hand-offs the review returns. review.js runs end to end with its agents
// answered and the item's comments kept here: on its own, after an audit child, forced again on a
// round whose verdicts and hand-offs are posted to reach the same verdict, another, the first
// one again and then fewer findings, in the next round with the markers listed newest first,
// over the round cap, and with a comment gh reads back only on the second try or never, or whose
// second read does not return or reports no action. The audit issue and the council comments
// come from the scripts' own builders. Reads {root, repository, records, item, maxRounds} on
// stdin; prints {commands, handoffs, reruns, prior, reread, unread}.
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const vm = require('vm')

const RUN_START = 'const input = normaliseArgs(args)'
const CHANGED = 'xtask/src/hook/handoff.rs'
const BASE = '1'.repeat(40)
const HEAD = '2'.repeat(40)
const NEXT_HEAD = '3'.repeat(40)
const PULL_REQUEST = 12
const HEREDOC_START = /<<'([A-Za-z0-9_]+)'$/
const HASH_STEP = '| sha256sum'

const input = JSON.parse(fs.readFileSync(0, 'utf8'))
const quote = input.records
  .flatMap(record => [`{"schema": "${record}", "item": 7}`, `<summary>${record}</summary>`, `"schema": "${record}_draft"`, `<summary>${record}0`])
  .join('; ')
// What the code-review finder reports unless a run says otherwise: a major finding in the change
// and a minor one in code the change did not touch.
const FOUND = [finding(CHANGED, 42, 'major', false), finding('xtask/src/orchestrate/handoff/tests.rs', 26, 'minor', true)]

function source(name) {
  const text = fs.readFileSync(path.join(input.root, '.agents/kit/workflows', name), 'utf8')
  if (!text.includes(RUN_START)) throw new Error(`${name} no longer starts its run with ${RUN_START}`)
  return text.replace(/^export const meta/m, 'const meta')
}

function declarations(name, names) {
  const text = source(name)
  const context = vm.createContext({ log() {} })
  vm.runInContext(`${text.slice(0, text.indexOf(RUN_START))}\nglobalThis.exported = { ${names.join(', ')} }`, context)
  return context.exported
}

async function run(name, answer, child, args) {
  const context = vm.createContext({
    args, log() {}, phase() {}, budget: { spent: () => 0 }, agent: answer,
    parallel: thunks => Promise.all(thunks.map(thunk => thunk().catch(() => null))),
    workflow: async () => {
      if (!child) throw new Error('no child workflow runs here')
      return child
    },
  })
  return vm.runInContext(`(async () => {\n${source(name)}\n})()`, context)
}

// Each command line of a publisher prompt, a here-document through its delimiter. It fails the
// run when a body's here-document does not start such a line, since that body would go unchecked.
// The lines of a captured body are data, so a here-document they quote is not counted.
function commands(origin, prompt) {
  const found = []
  let heredocs = 0
  const lines = prompt.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (HEREDOC_START.test(lines[i])) heredocs++
    const start = /^(?:First run: )?(gh .*)$/.exec(lines[i])
    if (!start) continue
    const delimiter = HEREDOC_START.exec(start[1])
    const end = delimiter ? lines.indexOf(delimiter[1], i + 1) : i
    const words = start[1].split(' ').filter(word => !word.startsWith('-')).slice(0, 3)
    found.push({ name: `${origin}-${found.length}-${words.join('-')}`, command: [start[1], ...lines.slice(i + 1, end + 1)].join('\n') })
    i = end
  }
  const posts = found.filter(({ command }) => command.includes('\n')).length
  if (!heredocs || posts !== heredocs) throw new Error(`${origin}: ${posts} of the publisher's ${heredocs} here-documents start a line as a gh command; every body must, and there must be one`)
  return found
}

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex')
}

// The item's comments on GitHub, and what gh prints for a lookup of them. The jq `select` is read
// in the two forms the scripts use, with the meaning gh's jq gives them: a body that contains a
// text, and a body with a line that starts with one.
function commentThread() {
  const comments = []
  const print = command => {
    const jq = /--jq '\.comments\[\] \| select\(\.body \| (.+)\) \| \.(url|body)'/.exec(command)
    const contains = jq && /^contains\("([^"]*)"\)$/.exec(jq[1])
    const line = jq && /^split\("\\n"\) \| any\(startswith\("([^"]*)"\)\)$/.exec(jq[1])
    if (!contains && !line) throw new Error(`no reading for the comment lookup ${command}`)
    const picks = body => (contains ? body.includes(contains[1]) : body.split('\n').some(text => text.startsWith(line[1])))
    return comments.filter(comment => picks(comment.body)).map(comment => `${comment[jq[2]]}\n`).join('')
  }
  return { comments, print }
}

// What gh prints for the hash step: nothing on the first read, as on a transient gh error, and
// the comment after that.
function readsOnSecondTry(thread) {
  let reads = 0
  return command => (reads++ ? thread.print(command) : '')
}

// The review's publisher on `thread`: it posts the verdict comment unless the lookup prints one,
// and reports the digest of what `read` prints for the hash step, as a model would copy it. A
// read-back action is that hash step alone.
function publisher(thread, read) {
  return text => ({
    actions: text.split(/^Action \d+: /m).slice(1).map((block, index) => {
      const lines = block.split('\n')
      const hash = lines.find(line => line.endsWith(HASH_STEP))
      if (!hash) return { index, outcome: 'posted', url: `posted ${index}`, error: '', sha256: '' }
      const lookup = lines.find(line => line.startsWith('First run: gh ') && line.includes(' --json comments '))
      const found = lookup ? thread.print(lookup).trim() : ''
      if (lookup && !found) thread.comments.push({ url: `comment ${thread.comments.length}`, body: /<<'(\w+)'\n([\s\S]*?)\n\1$/m.exec(block)[2] })
      const url = found || (lookup ? thread.comments[thread.comments.length - 1].url : '')
      return { index, outcome: lookup && !found ? 'posted' : 'exists', url, error: '', sha256: sha256(read(hash)) }
    }),
  })
}

// A hand-off comment as kit handoff posts it: one line, then the record collapsed under its schema.
function handoffComment(handoff) {
  const line = `Hand-off from ${handoff.agent}, attempt 1, round ${handoff.round}: **${handoff.status}**. ${handoff.summary}`
  return `${line}\n\n<details><summary>${handoff.schema}</summary>\n\n\`\`\`json\n${JSON.stringify(handoff, null, 2)}\n\`\`\`\n\n</details>\n`
}

// The evidence quotes a here-document start on a line of its own, as a finding about one would.
function finding(file, line, severity, preExisting) {
  return {
    path: file, line, category: 'correctness', severity, pre_existing: preExisting,
    claim: `The record reader drops ${quote}`, failure_scenario: `A comment that holds ${quote} is read as invalid.`,
    evidence: `let record = r#"${quote}"#;\nprintf hi <<'EOF'`, fix: `Accept ${quote}.`,
  }
}

// A library audit child whose run evidence has only the fields audit.js's schema makes its
// finder return.
function auditChild() {
  const { EVIDENCE } = declarations('audit.js', ['EVIDENCE'])
  const entry = Object.fromEntries(EVIDENCE.required.map(key => [key, EVIDENCE.properties[key].type === 'integer' ? 0 : key]))
  return { status: 'done', runs: [{ evidence: [entry] }], survivors: [], skipped: [] }
}

function priorFindings(prompt) {
  const lines = prompt.split('\n')
  const from = lines.findIndex(line => line.startsWith('Findings from earlier rounds'))
  return from === -1 ? [] : lines.slice(from + 1, lines.indexOf('Rules:', from))
}

// A review run on `thread`. `listed` orders the marker lines as the scope reports them, and a
// read-back agent answers as `readBack` says: through the publisher, with no action, or not at all.
async function review({ thread = commentThread(), read = thread.print, child = null, args = {}, found = FOUND, head = HEAD, listed = lines => lines, readBack = 'answers' } = {}) {
  const { MARKER, parseModels } = declarations('review.js', ['MARKER', 'parseModels'])
  const modelsToml = fs.readFileSync(path.join(input.root, '.agents/models.toml'), 'utf8')
  const models = parseModels(modelsToml)
  const markers = thread.comments.flatMap(comment => comment.body.split('\n')).filter(line => line.startsWith(`<!-- ${MARKER} `))
  const hunks = `--- a/${CHANGED}\n+++ b/${CHANGED}\n@@ -40,3 +40,9 @@`
  const scope = {
    mode: 'github', repo: input.repository, repo_exists: true, problems: [], pr: PULL_REQUEST, pr_state: 'OPEN', item: input.item,
    from_fork: false, base_sha: BASE, head_sha: head, labels: [], review_markers: listed(markers), writer_models: [models.sonnet],
    models_toml: modelsToml, max_findings: FOUND.length, max_review_rounds: input.maxRounds, trust_core_paths: '', changed_paths: [CHANGED],
    hunk_headers: hunks, state_lines: '',
  }
  const publish = publisher(thread, read)
  const prompts = { publish: '', find: '', readBacks: [] }
  const answer = async (text, opts) => {
    if (opts.label === 'scope') return scope
    if (opts.label === 'round diff') return { reachable: true, changed_paths: [CHANGED], hunk_headers: hunks, state_lines: '' }
    if (opts.phase === 'Find') {
      prompts.find = prompts.find || text
      return { findings: opts.label.startsWith('code-review ') ? found : [], checked_and_sound: [] }
    }
    if (opts.phase === 'Verify') return { verdict: 'UPHELD', severity: /"severity": "(\w+)"/.exec(text)[1], pre_existing: false, reason: `It holds: ${quote}`, quotes: [] }
    if (opts.label === 'read back') prompts.readBacks.push(text)
    else if (opts.label === 'publish') prompts.publish = text
    else throw new Error(`no answer for agent ${opts.label}`)
    if (opts.label === 'read back' && readBack !== 'answers') return readBack === 'no action' ? { actions: [] } : null
    return publish(text)
  }
  const before = thread.comments.length
  const result = await run('review.js', answer, child, args)
  if (!prompts.publish) throw new Error(`review.js published nothing: ${JSON.stringify(result)}`)
  const hash = prompts.publish.split('\n').find(line => line.endsWith(HASH_STEP))
  return {
    result, handoff: result.handoff, commands: commands('review', prompts.publish), hash, prior: priorFindings(prompts.find),
    readBacks: prompts.readBacks, posted: thread.comments.length - before,
  }
}

// What a review cites, beside the newest verdict comment on `thread` for its round, the verdict
// that comment shows, and how many comments the run posted against the `posts` it should.
function citation(run, thread, posts) {
  const lead = `eval-diff round ${run.handoff.round} of ${input.maxRounds} `
  const newest = thread.comments.filter(comment => comment.body.startsWith(lead)).pop()
  return {
    status: run.result.status, evidence: run.handoff.evidence, read_backs: run.readBacks, posted: run.posted, posts,
    newest: { log: newest.url, sha256: sha256(`${newest.body}\n`) }, shows: /\*\*([a-z-]+)\*\*/.exec(newest.body.split('\n')[0])[1],
  }
}

// A review whose verdict comment is never read back: what it returns beside the comment it posted
// and the hash command it gave its publisher, the `cause` its reason must name, and the digest of
// no input, which its reason must tell the agent never to cite.
function unreadComment(run, thread, cause) {
  return {
    status: run.result.status, evidence: run.handoff.evidence, read_backs: run.readBacks, reason: run.result.reason || '', cause, empty_digest: sha256(''),
    returned: { comment: run.result.comment || '', hash: run.result.hash || '' },
    posted: { comment: thread.comments.map(comment => comment.url).join(', '), hash: run.hash },
  }
}

function audit() {
  const script = declarations('audit.js', ['issueFor', 'publishPrompt'])
  const result = {
    prompt: 'A07', arm: 'power', closure: [], run_id: 'r1', title: `The record reader drops ${quote}`, label: 'CONFIRMED', severity: 3,
    proof: { status: 'not-reproduced' }, smallest_fix: `Accept ${quote}.`, checked_by: 'runner',
    evidence: [{ path: 'xtask/src/orchestrate/handoff/tests.rs', line: 26, quote }],
    verdicts: [{ model: 'opus', verdict: 'UPHELD', reason: quote }], fingerprint: 'f1', token: 'grdrau1',
  }
  const issue = script.issueFor(result, { scope: 'xtask', commit_sha: HEAD }, [])
  return commands('audit', script.publishPrompt(input.repository, [issue]))
}

function council() {
  const script = declarations('persona-council.js', ['seatBody', 'chairBody', 'postPrompt', 'SEATS'])
  const ctx = { issue: input.item, round: 1, head: HEAD, models: {} }
  const verdict = {
    verdict: 'block', spine_floor: ['P8'], floor_reason: quote, summary: quote,
    findings: [{ journey_step: quote, problem: quote, evidence: quote, fix: quote }],
    journeys: [{ journey: quote, outcome: 'gave-up', reason: quote, gave_up_at: quote }],
  }
  const chair = {
    floors: [{ floor: 'P8', seat: script.SEATS[0], why: quote }], summary: quote,
    merged: [{ problem: quote, seats: [script.SEATS[0]], from_block: true, fix: quote }],
    blocks: [{ seat: script.SEATS[0], needs: quote }], tensions: [{ seats: script.SEATS.slice(0, 2), what: quote }],
  }
  const seat = script.seatBody(script.SEATS[0], verdict, ctx, 'grdrseat1')
  const chaired = script.chairBody(chair, [{ ...verdict, seat: script.SEATS[0] }], ctx, 'grdrchair1')
  return [
    ...commands('council-seat', script.postPrompt(input.repository, input.item, 'grdrseat1', seat)),
    ...commands('council-chair', script.postPrompt(input.repository, input.item, 'grdrchair1', chaired)),
  ]
}

// The next round's scope lists the markers newest first, as when the newer verdicts are on the
// issue, whose lines it lists before the pull request's.
async function main() {
  const posted = commentThread()
  const handOff = run => posted.comments.push({ url: `comment ${posted.comments.length}`, body: handoffComment(run.handoff) })
  const forced = async (found, posts) => {
    const run = await review({ thread: posted, args: { force: true }, found })
    handOff(run)
    return { run, cited: citation(run, posted, posts) }
  }
  const alone = await review({ thread: posted })
  const { round } = alone.handoff
  handOff(alone)
  const same = await forced(FOUND, 0)
  const changed = await forced([], 1)
  const back = await forced(FOUND, 1)
  const fewer = await forced(FOUND.slice(0, 1), 1)
  const next = await review({ thread: posted, head: NEXT_HEAD, listed: lines => [...lines].reverse() })
  const audited = await review({ child: auditChild() })
  const capped = await review({ args: { round: input.maxRounds + 1 } })
  const flaky = commentThread()
  const reread = await review({ thread: flaky, read: readsOnSecondTry(flaky) })
  const lost = commentThread()
  const unread = await review({ thread: lost, read: () => '' })
  const stalled = commentThread()
  const unreturned = await review({ thread: stalled, read: () => '', readBack: 'not at all' })
  const actionless = commentThread()
  const unreported = await review({ thread: actionless, read: () => '', readBack: 'no action' })
  return {
    commands: [...alone.commands, ...audit(), ...council()],
    handoffs: {
      'without an audit': alone.handoff, 'after an audit': audited.handoff, 'on a forced re-review': changed.run.handoff,
      'back on the first verdict': back.run.handoff, 'in the next round': next.handoff, 'after a second read': reread.handoff,
      'over the round cap': capped.handoff,
    },
    reruns: {
      'with the same verdict': same.cited, 'with another verdict': changed.cited, 'with the first verdict again': back.cited,
      'with fewer findings': fewer.cited,
    },
    prior: { round: next.handoff.round, after: round, listed: next.prior, expected: fewer.run.result.findings.map(f => `- ${f.path}:${f.line} ${f.claim.slice(0, 120)}`) },
    reread: citation(reread, flaky, 1),
    unread: {
      'when gh prints nothing twice': unreadComment(unread, lost, 'two reads'),
      'when the second read does not return': unreadComment(unreturned, stalled, 'resuming this run reads it again'),
      'when the second read reports no action': unreadComment(unreported, actionless, 'two reads'),
    },
  }
}

main()
  .then(built => process.stdout.write(JSON.stringify(built)))
  .catch(error => {
    process.stderr.write(`${error.stack || error}\n`)
    process.exitCode = 1
  })
