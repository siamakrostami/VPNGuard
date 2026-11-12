import AppKit
let path = CommandLine.arguments[1]
let image = NSImage(size: NSSize(width: 1024, height: 1024))
image.lockFocus()
let base = NSBezierPath(roundedRect: NSRect(x: 34, y: 34, width: 956, height: 956), xRadius: 216, yRadius: 216)
NSGradient(starting: NSColor(calibratedRed: 0.11, green: 0.22, blue: 0.32, alpha: 1), ending: NSColor(calibratedRed: 0.025, green: 0.08, blue: 0.13, alpha: 1))!.draw(in: base, angle: -70)
let shield = NSBezierPath()
shield.move(to: NSPoint(x: 512, y: 819)); shield.curve(to: NSPoint(x: 234, y: 710), controlPoint1: NSPoint(x: 430, y: 771), controlPoint2: NSPoint(x: 327, y: 725))
shield.line(to: NSPoint(x: 248, y: 488)); shield.curve(to: NSPoint(x: 512, y: 199), controlPoint1: NSPoint(x: 256, y: 337), controlPoint2: NSPoint(x: 377, y: 240))
shield.curve(to: NSPoint(x: 776, y: 488), controlPoint1: NSPoint(x: 647, y: 240), controlPoint2: NSPoint(x: 768, y: 337)); shield.line(to: NSPoint(x: 790, y: 710))
shield.curve(to: NSPoint(x: 512, y: 819), controlPoint1: NSPoint(x: 697, y: 725), controlPoint2: NSPoint(x: 594, y: 771)); shield.close()
NSGradient(starting: NSColor(calibratedRed: 0.33, green: 0.92, blue: 0.76, alpha: 1), ending: NSColor(calibratedRed: 0.11, green: 0.58, blue: 0.75, alpha: 1))!.draw(in: shield, angle: -80)
let tick = NSBezierPath(); tick.move(to: NSPoint(x: 374,y: 508)); tick.line(to: NSPoint(x: 477,y: 409)); tick.line(to: NSPoint(x: 660,y: 612)); tick.lineWidth = 62; tick.lineCapStyle = .round; tick.lineJoinStyle = .round
NSColor(calibratedWhite: 0.98, alpha: 1).setStroke(); tick.stroke()
image.unlockFocus()
let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
