# Where is our head of challenges?

## Challenge Information

| Field | Value |
| --- | --- |
| Category | Misc (OSINT / Geolocation) |
| Points | 100 |
| Author | PGpenguin72 |
| Artifact | [`artifacts/chal.jpg`](artifacts/chal.jpg) |
| Flag | `THJCC{144.95,-37.81}` |

> Our Head of Challenges went abroad and took a photo during the trip. Can you
> determine where it was taken?
>
> Submit the location as latitude and longitude, rounded to two decimal places,
> in the format `THJCC{longitude,latitude}`.
> Example: `THJCC{121.56,25.04}`

## Overview

A single balcony photo (`chal.jpg`, 2160×2880). No coordinates are handed to us —
the task is pure visual OSINT: read the skyline, identify the city, then work out
where the *camera* stood and express it as `longitude,latitude` to two decimals.

The path is:

1. Confirm there is no metadata shortcut.
2. Read the corporate signage and architecture to pin the city.
3. Use the relative positions of several named towers to work out which way the
   camera faced and, from that, which side of the CBD the balcony is on.
4. Convert that vantage point to a rounded coordinate.

The answer is a balcony in the **western Melbourne CBD**, looking east across the
Collins Street skyline: `THJCC{144.95,-37.81}`.

## 1. No Metadata Shortcut

Geolocation challenges often hide the answer in EXIF GPS tags, so check first:

```bash
exiftool -a -u -g1 chal.jpg | grep -iE 'gps|location|make|model|date|software'
```

```text
(nothing — no GPS, no camera Make/Model, no software tag)
```

The file is a bare JFIF with every identifying tag stripped. There is no
shortcut; the location has to come out of the pixels.

## 2. Reading the Skyline

Several elements in the frame are individually diagnostic. Cropping and enhancing
each one:

| Clue | What it is |
| --- | --- |
| Tower with white/blue facade, a **`Z` + "ZURICH"** sign and a tall mast | **120 Collins Street**, Melbourne (265 m, the "Zurich Tower") |
| Glass tower with a stepped/faceted crown, **"SUNCORP"** signage | Suncorp's Melbourne office building |
| Slim glass tower behind it | **101 Collins Street** |
| Very slim tower, black-and-white **basket-weave facade**, angular **"M"** crown | a distinctive northern-CBD residential tower |
| Cars in the street below driving on the **left** | left-hand traffic → Australia |

Any one of "ZURICH" + "SUNCORP" + left-hand traffic already forces the city.
Together they are conclusive: this is **Melbourne, Australia**, specifically the
central business district. Zurich Insurance's 120 Collins Street and Suncorp are
both Melbourne CBD fixtures.

`120 Collins Street` sits at **`-37.8138, 144.9695`**, which becomes the anchor
for everything that follows.

## 3. Which Way Is the Camera Facing?

The flag needs two-decimal precision (~1 km), so "somewhere in Melbourne" is not
enough — we have to place the *balcony*, and that means recovering the camera's
orientation from the relative positions of the named towers.

Two facts fix it:

- **We can read the ZURICH sign.** That signage on 120 Collins faces roughly
  **west**, toward the main body of the CBD. If the sign is legible and pointed
  toward us, the camera is on the **western** side of 120 Collins.
- **101 Collins and Suncorp appear to the *right* of 120 Collins.** Those
  buildings are just **south** of 120 Collins. For south to render on the
  right-hand side of the frame, the camera must be **facing east** (facing east:
  left is north, right is south).

So the camera is **west of the Collins Street core, looking east**. The slim "M"
basket-weave tower and the large adjacent residential tower on the immediate left
are therefore to the **north** — consistent with the northern/western pocket of
the CBD where the apartment towers cluster.

This is also why the earlier naïve guesses (placing the camera *north* of
120 Collins and reading a longitude of 144.96–144.97) are wrong: the camera is
not north of the tower, it is **west** of it, looking back east.

## 4. From Vantage Point to Coordinate

The western edge of the Hoddle Grid runs down **Spencer Street (≈144.95 E)** and
**King Street (≈144.956 E)**; this strip is full of high-rise residential towers
with exactly this east-facing balcony view over the Collins Street skyline. A
high floor there, looking east, sees 120 Collins in the mid-distance with
101 Collins and Suncorp to its right — precisely the framing in the photo.

Reading off the balcony's position:

```text
longitude ≈ 144.95   (western CBD, ~Spencer Street strip)
latitude  ≈ -37.81   (CBD core latitude; southern hemisphere → negative)
```

Both the apartment and 120 Collins round to **latitude -37.81**. The longitude is
what separates the vantage point (western CBD, `144.95`) from the landmark it is
looking at (`120 Collins`, `144.97`) — and the challenge asks for where the photo
was *taken*, i.e. the balcony.

The format is `THJCC{longitude,latitude}` (the worked example `THJCC{121.56,25.04}`
is Taipei 101 at 121.56 E, 25.04 N), so longitude comes first:

```text
THJCC{144.95,-37.81}
```

## Notes on Precision

Two-decimal rounding (~1.1 km in latitude, ~0.9 km in longitude at this latitude)
is coarse enough that the whole CBD collapses to `-37.81` in latitude, but fine
enough that the **east–west** placement matters: 120 Collins itself rounds to
`144.97`, whereas the balcony one grid-width to the west rounds to `144.95`. The
entire difficulty of the challenge is resisting the urge to submit the coordinate
of the *landmark* and instead recovering the coordinate of the *camera*. Getting
the facing direction right (camera west, looking east) is what yields the correct
western-CBD longitude.

## Lessons

- **Check EXIF first, but expect it stripped.** When it is, the skyline is the data.
- **Corporate signage geolocates fast.** "ZURICH" + "SUNCORP" + left-hand traffic
  pins Melbourne before any architecture analysis.
- **A landmark's coordinate is not the photo's coordinate.** The question is where
  the camera stood; use the landmark only as an anchor for triangulation.
- **Relative left/right of known buildings gives you the facing direction**, and
  the facing direction is what fixes the correct side of the city — here, the
  western CBD (`144.95`), not the northern one (`144.96/144.97`).

## Flag

```text
THJCC{144.95,-37.81}
```
