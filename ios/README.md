# MealMetrics — iOS

A minimal SwiftUI meal-tracking app whose visual language mirrors the
agent-signing landing page (`landing_page/index.html`): paper background,
ink cards with a sage→rust gradient stripe, serif headlines with italic
rust accents, and uppercase monospaced labels.

## Features

- **Key metrics dashboard** — calories today, meals today, logging streak,
  and photos logged, plus a "today summary" card styled after the site's
  floating signature card.
- **Photo logging** — attach a meal photo from the photo library
  (`PhotosPicker`) or take one with the camera.
- **Local persistence** — meals are stored as JSON and JPEGs in the app's
  documents directory. No account or backend required.

## Requirements

- Xcode 16 or newer
- iOS 17.0+ (device or simulator)

## Running

```sh
open ios/MealMetrics.xcodeproj
```

Select the *MealMetrics* scheme and an iPhone simulator, then run (⌘R).
To run on a device, set your development team under
*Signing & Capabilities*. The camera option only appears on hardware with
a camera; in the simulator, use *Choose photo*.

## Structure

| File | Purpose |
| --- | --- |
| `MealMetricsApp.swift` | App entry point |
| `Theme.swift` | Colors and type ramp mapped from the site's CSS tokens |
| `Models.swift` | `Meal` model, `MealStore` persistence + metric computations |
| `Components.swift` | Reusable styled views (section labels, metric cards, ink cards, buttons) |
| `DashboardView.swift` | Metrics dashboard and recent-meals list |
| `AddMealView.swift` | Meal entry form with photo picker and camera capture |
| `MealDetailView.swift` | Meal detail with photo and delete action |
