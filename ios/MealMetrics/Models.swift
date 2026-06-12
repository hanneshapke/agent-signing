import Foundation
import UIKit

enum MealType: String, Codable, CaseIterable, Identifiable {
    case breakfast, lunch, dinner, snack

    var id: String { rawValue }
    var label: String { rawValue.capitalized }
}

struct Meal: Identifiable, Codable, Hashable {
    var id = UUID()
    var name: String
    var calories: Int
    var type: MealType
    var date: Date
    var imageFilename: String?
}

/// Persists meals as JSON plus JPEG photos in the app's documents directory.
@MainActor
final class MealStore: ObservableObject {
    @Published private(set) var meals: [Meal] = []

    private let fileURL: URL
    private let imagesDirectory: URL

    init() {
        let documents = FileManager.default.urls(
            for: .documentDirectory, in: .userDomainMask
        )[0]
        fileURL = documents.appendingPathComponent("meals.json")
        imagesDirectory = documents.appendingPathComponent(
            "meal-images", isDirectory: true
        )
        try? FileManager.default.createDirectory(
            at: imagesDirectory, withIntermediateDirectories: true
        )
        load()
    }

    // MARK: - Mutations

    func add(name: String, calories: Int, type: MealType, image: UIImage?) {
        var meal = Meal(name: name, calories: calories, type: type, date: .now)
        if let image, let data = image.jpegData(compressionQuality: 0.8) {
            let filename = "\(meal.id.uuidString).jpg"
            try? data.write(to: imagesDirectory.appendingPathComponent(filename))
            meal.imageFilename = filename
        }
        meals.insert(meal, at: 0)
        save()
    }

    func delete(_ meal: Meal) {
        if let filename = meal.imageFilename {
            try? FileManager.default.removeItem(
                at: imagesDirectory.appendingPathComponent(filename)
            )
        }
        meals.removeAll { $0.id == meal.id }
        save()
    }

    func image(for meal: Meal) -> UIImage? {
        guard let filename = meal.imageFilename else { return nil }
        return UIImage(
            contentsOfFile: imagesDirectory.appendingPathComponent(filename).path
        )
    }

    // MARK: - Key metrics

    var mealsToday: [Meal] {
        meals.filter { Calendar.current.isDateInToday($0.date) }
    }

    var caloriesToday: Int {
        mealsToday.reduce(0) { $0 + $1.calories }
    }

    var photoCount: Int {
        meals.filter { $0.imageFilename != nil }.count
    }

    var lastMeal: Meal? {
        meals.max { $0.date < $1.date }
    }

    /// Consecutive days (ending today, or yesterday if today is still empty)
    /// with at least one logged meal.
    var dayStreak: Int {
        let calendar = Calendar.current
        let days = Set(meals.map { calendar.startOfDay(for: $0.date) })
        guard !days.isEmpty else { return 0 }

        var day = calendar.startOfDay(for: .now)
        if !days.contains(day) {
            guard let yesterday = calendar.date(byAdding: .day, value: -1, to: day),
                  days.contains(yesterday)
            else { return 0 }
            day = yesterday
        }

        var streak = 0
        while days.contains(day) {
            streak += 1
            guard let previous = calendar.date(byAdding: .day, value: -1, to: day)
            else { break }
            day = previous
        }
        return streak
    }

    // MARK: - Persistence

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([Meal].self, from: data)
        else { return }
        meals = decoded.sorted { $0.date > $1.date }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(meals) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
