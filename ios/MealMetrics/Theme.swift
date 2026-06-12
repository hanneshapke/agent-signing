import SwiftUI

/// Design tokens lifted from the agent-signing landing page
/// (landing_page/index.html) so the app shares the site's visual language.
enum Theme {
    // Palette — matches the site's CSS custom properties.
    static let ink = Color(hex: 0x0A0A0B)
    static let paper = Color(hex: 0xF4F1EB)
    static let cream = Color(hex: 0xEBE7DD)
    static let rust = Color(hex: 0xC4501A)
    static let rustLight = Color(hex: 0xE8693A)
    static let sage = Color(hex: 0x5A7A64)
    static let sageLight = Color(hex: 0x7A9A84)
    static let slate = Color(hex: 0x6B6A67)
    static let ghost = Color.black.opacity(0.06)
    static let paperFaint = Color(hex: 0xF4F1EB).opacity(0.55)

    // Type — serif display, mono labels, sans body (site uses
    // Instrument Serif / DM Mono / Satoshi; we map to system designs).
    static func serif(_ size: CGFloat) -> Font {
        .system(size: size, design: .serif)
    }

    static func serifItalic(_ size: CGFloat) -> Font {
        .system(size: size, design: .serif).italic()
    }

    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }

    static func sans(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}
