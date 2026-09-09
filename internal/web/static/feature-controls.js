/*
 * Feature controls layered over the dashboard's core renderers.
 *
 * Kept separate from app.js so experimental controls stay small and easy to
 * remove or promote once the underlying runtime contracts settle. This file is
 * a classic script loaded after app.js, so it deliberately reuses the existing
 * html/raw helpers, page registry and API client rather than introducing a
 * second UI framework.
 */
(() => {
  const originalLocalDnssecCard = localDnssecCard;
  const originalAccessBadge = accessBadge;
  const originalNetworksMounted = pages.networks.mounted;

  function daddyboundModeCard(data) {
    const learn = !!data && data.mode === 'observe';
    const enforcing = !!data && data.enforcing === true;

    return html`
      <div class="card section">
        <div class="card-head">
          <div>
            <div class="card-eyebrow">Experimental</div>
            <h2>Daddybound DNSSEC engine ${raw(claimChip('experimental'))}</h2>
            <p>
              DNS Daddy's local validator can learn beside the normal resolution path
              before it is ever trusted to make a client-facing decision.
            </p>
          </div>
          <div class="row-end">
            ${raw(learn
              ? html`<span class="badge ok">Learn active</span>`
              : html`<span class="badge">Off</span>`)}
          </div>
        </div>

        <div class="grid grid-2">
          <div>
            <div class="label muted small">DADDYBOUND MODE</div>
            <div class="row note-tight" role="group" aria-label="Daddybound mode">
              <span class="btn ${learn ? 'btn-primary' : 'btn-ghost'} btn-sm" aria-current="${learn ? 'true' : 'false'}">
                Learn
              </span>
              <button class="btn btn-ghost btn-sm" type="button" disabled
                      title="Live stays unavailable until Daddybound enforcement is implemented and tested.">
                Live
              </button>
            </div>
            <p class="muted small note-tight">
              <strong>Learn</strong> is the safe shadow mode. Daddybound independently
              validates the names clients request, records its verdict and compares it
              with the upstream view. It never changes the response.
            </p>
          </div>

          <div>
            <div class="label muted small">DNSSEC DECISION SOURCE</div>
            <div class="stack note-tight">
              <div class="rec">
                <div class="rec-main">
                  <div class="rec-title"><strong>Upstream resolution path</strong> <span class="badge ok">Current</span></div>
                  <p class="rec-note">Still decides the answer the client receives.</p>
                </div>
              </div>
              <div class="rec">
                <div class="rec-main">
                  <div class="rec-title"><strong>Daddybound</strong> <span class="badge">Shadow only</span></div>
                  <p class="rec-note">Cannot become the decision source in this build.</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        ${raw(learn
          ? html`<p class="muted small note-tight">
              The backend configuration name is <span class="mono">observe</span>;
              the product calls that behaviour <strong>Learn</strong>. Live remains disabled
              because <span class="mono">enforce</span> is explicitly refused at startup rather
              than pretending Daddybound protects traffic before that path exists.
            </p>`
          : html`<p class="muted small note-tight">
              Daddybound is not running. Set
              <span class="mono">dns.local_dnssec_validation: observe</span> and restart to enter
              Learn mode. Fresh installs ship with Learn enabled by default.
            </p>`)}

        ${raw(enforcing
          ? html`<p class="rec-note is-warn">This server reports Daddybound enforcement. The dashboard build did not expect that capability yet; review the running version before relying on it.</p>`
          : '')}
      </div>`;
  }

  // Keep the existing detailed telemetry card — it already has careful
  // wording around stored/observed populations and disagreement counts — and
  // put the product-level Learn/Live state immediately before it.
  localDnssecCard = function (data) {
    const telemetry = String(originalLocalDnssecCard(data))
      .replace('Local DNSSEC validation — observing', 'Daddybound validation telemetry — Learn')
      .replace('Local DNSSEC validation ', 'Daddybound validation telemetry ');
    return daddyboundModeCard(data) + telemetry;
  };

  // The system Default row is not a CIDR-bearing Network. Its access bit gates
  // the configured bootstrap pool for unmatched clients, so calling it
  // "Grants nothing" is now both confusing and false.
  accessBadge = function (n) {
    if (!n || n.id !== 'n_default') return originalAccessBadge(n);
    if (n.enabled === false) {
      return html`<span class="badge" title="The Default policy is disabled, so ad-hoc access is off.">Disabled</span>`;
    }
    if (n.allowResolver) {
      return html`<span class="badge ok"
        title="Unmatched clients inside dns.allowed_client_cidrs may resolve under the Default policy. This does not widen the configured client ACL.">Ad-hoc access on</span>`;
    }
    return html`<span class="badge"
      title="Unmatched clients are refused over ordinary DNS unless an explicit permitted Network covers them. Loopback remains available.">Ad-hoc access off</span>`;
  };

  pages.networks.mounted = async function () {
    if (originalNetworksMounted) await originalNetworksMounted.call(this);

    const box = document.querySelector('[data-access="n_default"]');
    if (!box) return;

    const label = box.closest('label');
    const copy = label && label.querySelector('span');
    if (copy) copy.textContent = 'Ad-hoc access';
    if (label) {
      label.title = 'Allow unmatched clients that are already inside dns.allowed_client_cidrs to use the Default policy.';
    }
    box.dataset.name = 'Ad-hoc clients';

    const record = box.closest('.rec');
    if (record) {
      const main = record.querySelector('.rec-main');
      if (main && !main.querySelector('[data-default-access-note]')) {
        const note = document.createElement('p');
        note.className = 'rec-note';
        note.dataset.defaultAccessNote = '1';
        note.textContent = box.checked
          ? 'Ad-hoc mode is on. Unmatched clients inside the configured client ACL may resolve under the Default policy.'
          : 'Off by default on new installs. Turn this on to let unmatched clients inside the configured client ACL resolve under the Default policy; it never expands that ACL.';
        main.append(note);
      }

      // Default is now a system access setting as well as the policy fallback;
      // deleting it from the normal UI would make the control disappear. The
      // API remains explicit for recovery/advanced administration.
      const del = record.querySelector('[data-delete-network="n_default"]');
      if (del) del.hidden = true;
    }
  };
})();
