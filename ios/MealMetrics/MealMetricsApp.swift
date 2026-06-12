import SwiftUI

@main
struct MealMetricsApp: App {
    @StateObject private var store = MealStore()

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(store)
                .tint(Theme.rust)
        }
    }
}
