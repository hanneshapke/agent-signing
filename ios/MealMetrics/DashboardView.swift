import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var store: MealStore
    @State private var showAddMeal = false

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.paper.ignoresSafeArea()
                ScrollView {
                    VStack(alignment: .leading, spacing: 32) {
                        header
                        hero
                        metrics
                        todaySummary
                        recentMeals
                    }
                    .padding(.horizontal, 24)
                    .padding(.top, 12)
                    .padding(.bottom, 24)
                }
            }
            .safeAreaInset(edge: .bottom) { logMealButton }
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Meal.self) { meal in
                MealDetailView(meal: meal)
            }
            .sheet(isPresented: $showAddMeal) {
                AddMealView()
            }
        }
    }

    // MARK: - Header (site nav: sigil + mono wordmark + badge)

    private var header: some View {
        HStack {
            HStack(spacing: 9) {
                ZStack {
                    Circle().strokeBorder(Theme.ink, lineWidth: 2)
                    Image(systemName: "fork.knife")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Theme.ink)
                }
                .frame(width: 28, height: 28)
                Text("meal-metrics")
                    .font(Theme.mono(14, weight: .medium))
                    .foregroundStyle(Theme.ink)
            }
            Spacer()
            HStack(spacing: 6) {
                Circle().fill(Theme.sage).frame(width: 6, height: 6)
                Text(
                    Date.now
                        .formatted(.dateTime.weekday(.abbreviated).month(.abbreviated).day())
                        .uppercased()
                )
                .font(Theme.mono(10))
                .kerning(1)
            }
            .foregroundStyle(Theme.sage)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .overlay(Capsule().strokeBorder(Theme.sageLight, lineWidth: 1))
        }
    }

    // MARK: - Hero (serif headline with italic rust word)

    private var hero: some View {
        VStack(alignment: .leading, spacing: 14) {
            (
                Text("Know your meals.\nLog ")
                + Text("everything.")
                    .italic()
                    .foregroundColor(Theme.rust)
            )
            .font(Theme.serif(40))
            .foregroundColor(Theme.ink)
            .lineSpacing(2)

            Text("Track what you eat, photograph every plate, and watch your metrics move.")
                .font(Theme.sans(15))
                .foregroundStyle(Theme.slate)
                .lineSpacing(4)
        }
    }

    // MARK: - Key metrics grid

    private var metrics: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionLabel(text: "Key Metrics")
            LazyVGrid(
                columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible())],
                spacing: 12
            ) {
                MetricCard(
                    value: "\(store.caloriesToday)",
                    unit: "kcal",
                    title: "Calories Today"
                )
                MetricCard(
                    value: "\(store.mealsToday.count)",
                    title: "Meals Today"
                )
                MetricCard(
                    value: "\(store.dayStreak)",
                    unit: store.dayStreak == 1 ? "day" : "days",
                    title: "Logging Streak"
                )
                MetricCard(
                    value: "\(store.photoCount)",
                    title: "Photos Logged"
                )
            }
        }
    }

    // MARK: - Today summary (the site's floating signature card)

    private var todaySummary: some View {
        InkCard {
            InkCardRow(key: "last_meal", value: store.lastMeal?.name ?? "—")
            InkCardRow(key: "calories_today", value: "\(store.caloriesToday) kcal")
            InkCardRow(key: "photos_logged", value: "\(store.photoCount)")

            Rectangle()
                .fill(Theme.paper.opacity(0.1))
                .frame(height: 1)
                .padding(.vertical, 2)

            Text(
                store.dayStreak > 0
                    ? "✓ on track · \(store.dayStreak)-day streak"
                    : "· log a meal to start your streak"
            )
            .font(Theme.mono(11))
            .foregroundStyle(Theme.sageLight)
        }
    }

    // MARK: - Recent meals

    private var recentMeals: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionLabel(text: "Recent Meals")
            if store.meals.isEmpty {
                emptyState
            } else {
                VStack(spacing: 10) {
                    ForEach(store.meals.prefix(10)) { meal in
                        NavigationLink(value: meal) {
                            MealRow(meal: meal)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "camera")
                .font(.system(size: 22))
                .foregroundStyle(Theme.slate)
            Text("No meals logged yet")
                .font(Theme.sans(15, weight: .semibold))
                .foregroundStyle(Theme.ink)
            Text("Photograph your first plate to start your streak.")
                .font(Theme.sans(13))
                .foregroundStyle(Theme.slate)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 36)
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(
                    Theme.slate.opacity(0.3),
                    style: StrokeStyle(lineWidth: 1, dash: [5, 4])
                )
        )
    }

    private var logMealButton: some View {
        Button {
            showAddMeal = true
        } label: {
            Text("+ LOG A MEAL")
        }
        .buttonStyle(PrimaryButtonStyle())
        .padding(.horizontal, 24)
        .padding(.top, 8)
        .padding(.bottom, 4)
        .background(Theme.paper.opacity(0.92))
    }
}

struct MealRow: View {
    @EnvironmentObject private var store: MealStore
    let meal: Meal

    var body: some View {
        HStack(spacing: 14) {
            thumbnail
            VStack(alignment: .leading, spacing: 4) {
                Text(meal.name)
                    .font(Theme.sans(15, weight: .semibold))
                    .foregroundStyle(Theme.ink)
                    .lineLimit(1)
                Text(
                    "\(meal.type.label) · "
                    + meal.date.formatted(date: .abbreviated, time: .shortened)
                )
                .font(Theme.mono(11))
                .foregroundStyle(Theme.slate)
            }
            Spacer()
            Text("\(meal.calories) kcal")
                .font(Theme.mono(11, weight: .medium))
                .foregroundStyle(Theme.sage)
        }
        .padding(14)
        .background(Color.white.opacity(0.55))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(
            RoundedRectangle(cornerRadius: 6)
                .strokeBorder(Theme.ghost, lineWidth: 1)
        )
    }

    @ViewBuilder
    private var thumbnail: some View {
        if let image = store.image(for: meal) {
            Image(uiImage: image)
                .resizable()
                .scaledToFill()
                .frame(width: 52, height: 52)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        } else {
            RoundedRectangle(cornerRadius: 6)
                .fill(Theme.cream)
                .frame(width: 52, height: 52)
                .overlay(
                    Image(systemName: "fork.knife")
                        .font(.system(size: 16))
                        .foregroundStyle(Theme.slate)
                )
        }
    }
}

#Preview {
    DashboardView()
        .environmentObject(MealStore())
}
