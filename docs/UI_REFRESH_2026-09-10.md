# Airlock interface refresh - 10 September 2026

The local platform was restarted successfully at `http://127.0.0.1:8001`.
This is an interface/workflow polish pass, not production deployment approval.

## Scope

- The public homepage uses original, interactive woven-fabric artwork. The
  design takes cues from Palantir's public-site typography and broad sections;
  no Palantir branding, media, or proprietary application screens are copied.
- The console has a redesigned workspace shell, organization selector, identity
  area, navigation, light/dark surfaces, tables, forms, drawers, and command search.
- Overview prioritizes inventory, modeled exposure, the existing risk map, and
  next actions. Forecasts and longer capability descriptions remain accessible
  in expandable sections. Security advisories keep a visible summary.
- Removed arbitrary overview progress bars and the prominent heuristic Q-Day
  ring. Forecast values remain explicitly modeled; unavailable inventory does
  not appear as a measured zero.
- Mobile navigation has a close button, backdrop, Escape support, a focus loop,
  and an inert background. Theme switching changes CSS without refetching data
  or clearing form contents.
- Live risk-panel refresh rebinds replaced action buttons and reports partial
  source failures instead of presenting retained values as a fresh full update.
- Administration and traffic monitoring share the new visual treatment while
  preserving credentials, role restrictions, source filters, and exports.
- Eleven public information pages share navigation, typography, and an original
  editorial layout. Legal and security text is preserved, not newly certified.

## Local verification

- Full E2E smoke: passed across 23 console views, public pages, authenticated
  platform administration, and traffic exports. Protected/unconfigured optional
  endpoints still return expected 400/403/404 responses; this does not validate
  every external integration.
- Admin workspace regression: passed, including source failure handling,
  cancellation, role controls, sign-out, traffic filters, and mobile layout.
- New console workspace smoke: passed. Covers both themes, no theme-triggered
  fetches, command search, disclosure panels, desktop collapse, mobile focus and
  routing at 320/390/768px, unavailable inventory, and all 11 public pages at
  mobile/desktop widths. Added to CI.
- Targeted backend launch tests: 3 passed, with 5 existing deprecation warnings.
- Launch collateral check: passed. Console inline JavaScript and CI YAML parse;
  backend/frontend console copies match. No full backend-suite rerun was needed
  for this frontend-only change.

## Public fabric follow-up

- Replaced the landscape with three interwoven WebGL ribbons, directional
  lighting, moving highlights, and mouse-responsive orientation. Discover,
  Protect, and Prove controls change the composition and the product chapter.
  Chapter tabs also update the hero controls, including keyboard navigation.
- Tightened the hero, introduction, chapter diagrams, resources, and footer.
  At a 1440x960 viewport the hero measures 634px and the page about 3555px;
  the complete main readiness claim is visible in the first viewport.
- Added a second animated evidence-boundary weave and brighter product flows.
  These are labeled architecture illustrations, not customer traffic or proof
  of a running tunnel. Public service health still comes from `/status`.
- Rendering is capped at 30 frames/second and roughly one million canvas
  pixels. Offscreen and hidden-page motion suspends; pause is persistent and
  reduced-motion preferences take priority. CSS artwork remains available
  without WebGL, and content remains readable without JavaScript.
- Extended landing browser smoke passed: actual changing pixels, all three
  modes while paused, synchronized tabs, compact layout, rendering budget,
  both fabrics' pause/offscreen behavior, reduced motion, public links, and
  health refresh/failure handling. The no-WebGL case checks frozen animation
  timelines and allows only one RGB level of browser texture dithering.
- Checked desktop/mobile screenshots and widths from 320 through 1920px;
  no horizontal overflow. WebGL context-loss fallback and recovery passed.
  Targeted launch tests passed again (3 tests, 5 existing deprecation warnings),
  as did the launch collateral check. Broader console/admin checks above belong
  to the earlier workspace pass; this follow-up changes only the public landing
  assets, landing smoke test, and this review note.

## Review links

- Public website: `http://127.0.0.1:8001/?v=20260910-fabric2`
- Customer console: `http://127.0.0.1:8001/ui/?v=20260910#overview`
- Platform administration: `http://127.0.0.1:8001/vendor-admin/?v=20260910`
- Traffic: `http://127.0.0.1:8001/vendor-admin/traffic.html?v=20260910`
- Security: `http://127.0.0.1:8001/security`
- Pricing: `http://127.0.0.1:8001/pricing`

Refer to the launch review (maintained privately) and a fresh deployment gate run for launch
requirements. Appearance and passing UI tests do not replace production identity,
tenant-isolation, infrastructure, integration, and contract validation.
