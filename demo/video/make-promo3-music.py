"""Score for the free-and-open three-minute commercial (render-promo3.js).

Same instrument and arrangement as make-film-music.py, re-timed to where this
film's acts actually fall on the 120 BPM grid (a bar is 2 s, ninety bars is
180 s):

    bars  0-6    the problem lines        drone, sub, bell
    bars  7-13   the product appears      pad joins
    bars 14-32   one domain, free         eighth-note figure, halved kick
    bars 33-55   the whole estate         full: kick on the beat, hats
    bars 56-71   evidence, "isn't any"    thins so the words carry
    bars 72-79   free, MIT, a workspace   sixteenths and a rising sweep
    bars 80-89   "No service-level        resolve: one chord, no pulse,
                 agreement." to the end   so the honest line lands in quiet

    backend/.venv/Scripts/python.exe demo/video/make-promo3-music.py
"""
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("film_music", HERE / "make-film-music.py")
film = importlib.util.module_from_spec(spec)
spec.loader.exec_module(film)

(film.OPEN_END, film.PAD_IN, film.PULSE_IN, film.FULL_IN,
 film.THIN_IN, film.BUILD_IN, film.RESOLVE) = 7, 7, 14, 33, 56, 72, 80

if "--out" not in sys.argv:
    sys.argv += ["--out", str(HERE / "morrow-promo3-music.wav")]
film.main()
