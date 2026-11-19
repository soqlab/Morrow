"""The front page's first screen, rendered on the server into the instrument page.

"/" is the same file as every instrument view (static/instrument.html). Here its empty ``#main`` is
given the hero: the question, the domain box with its Check button and the quiet line under it. So
the largest text on the page is painted with the first byte of CSS, before any script runs, and the
box works without JavaScript (it submits to /plain/go, the script-free check).

static/home-story.js takes this markup over when it runs: the check answers in place, and the rest
of the story (the share of sites ready, the rows of names, Done, the sectors, the full board) is
drawn from the public API below the fold. The live numbers are never written here: a page served
from cache would show a stale count, and the rule is that a number on screen came from an API
answer in this page load.
"""

from __future__ import annotations

#: Where the hero goes, and the parts of the page the home view changes. All three must be found in
#: static/instrument.html, or the page is served as it is (the script then draws the old home view).
MAIN_SLOT = ('<div id="main"><noscript><p>This view needs JavaScript. The <a href="/plain">plain version</a> '
             'works without it.</p></noscript></div>')
SAY = '<p class="i-say" id="say" aria-live="polite">Loading.</p>'
BODY = '<body class="ins" data-ch="grade">'

#: The question, word by word. Each word comes in once from a blurred copy of itself (the copy is
#: blurred and fades out, the word fades in: static/home-story.css animates transform and opacity
#: only), and "quantum-safe?" carries a shine that sweeps it three times and stops.
WORDS = ("Is", "your", "website")

HERO = (
    '<div id="main" class="hs" data-home-story="1">'
    '<section class="hs-hero" id="hs-hero" aria-labelledby="hs-h1">'
    '<div class="hs-glow" aria-hidden="true"></div>'
    '<p class="hs-live" id="hs-live"><span class="hs-dot" id="hs-dot" aria-hidden="true"></span>'
    '<span><b class="hs-num" id="hs-sites">&nbsp;</b> <span id="hs-sites-t">sites checked this week</span></span></p>'
    '<h1 class="hs-h1" id="hs-h1">'
    + " ".join(f'<span class="w w{i + 1}"><span class="wb" aria-hidden="true">{w}</span>{w}</span>' for i, w in enumerate(WORDS))
    + ' <em class="w w4"><span class="wb" aria-hidden="true">quantum&#8209;safe?</span><span class="hs-grad">quantum&#8209;safe?</span>'
      '<span class="hs-shine" aria-hidden="true"><span>quantum&#8209;safe?</span></span></em></h1>'
    '<form class="hs-check i-safe" id="home-form" action="/plain/go" method="get" novalidate>'
    '<label class="sr-only" for="home-q">Your website&rsquo;s address</label>'
    '<div class="hs-box"><textarea id="home-q" name="d" rows="1" autocomplete="url" autocapitalize="none" '
    'spellcheck="false" inputmode="url" placeholder="yourcompany.com" aria-describedby="home-hint"></textarea>'
    '<button type="submit" class="hs-btn" id="hs-go">Check it</button></div>'
    '<p class="hs-sub" id="home-hint" aria-live="polite">Free. No account. Takes seconds. Then the fix.</p>'
    '<div class="hs-quiet" id="hs-quiet"></div>'
    '<p class="hs-you i-you"><span class="i-you-size" aria-hidden="true">'
    "You're connected to Morrow with X25519MLKEM768 &mdash; classical. Try a current Chrome, Edge, Firefox or Safari."
    '</span><span id="home-conn"></span></p>'
    '<p class="hs-back i-back" id="home-back" aria-live="polite" hidden></p>'
    "</form>"
    '<div class="hs-answer" id="hs-answer" aria-live="polite"></div>'
    '<div id="paste-out" class="pa-wrap"></div>'
    '<noscript><p class="hs-sub">The live parts of this page need JavaScript. The box above still checks a '
    'domain, and the <a href="/plain">plain version</a> has everything without it.</p></noscript>'
    "</section>"
    '<div id="hs-story"></div>'
    "</div>"
)


def render(page: str) -> str:
    """instrument.html with the hero in ``#main``; unchanged if any marker is missing."""
    if MAIN_SLOT not in page or SAY not in page or BODY not in page:
        return page
    return (page.replace(MAIN_SLOT, HERO, 1)
                .replace(SAY, '<p class="i-say" id="say" aria-live="polite" hidden></p>', 1)
                .replace(BODY, '<body class="ins hs-page" data-ch="grade">', 1))
