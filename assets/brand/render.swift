// Renders an SVG to a PNG of the given pixel size, with AppKit's own SVG
// support (no other tools): `render in.svg out.png width height`.

import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 5,
      let width = Int(arguments[3]), let height = Int(arguments[4]),
      let image = NSImage(contentsOf: URL(fileURLWithPath: arguments[1])),
      let bitmap = NSBitmapImageRep(
          bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
          bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
          colorSpaceName: .calibratedRGB, bytesPerRow: 0, bitsPerPixel: 0
      )
else {
    FileHandle.standardError.write(Data("usage: render in.svg out.png width height\n".utf8))
    exit(2)
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
image.draw(in: NSRect(x: 0, y: 0, width: width, height: height))
NSGraphicsContext.restoreGraphicsState()
guard let png = bitmap.retagging(with: .sRGB)?.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("cannot encode \(arguments[2])\n".utf8))
    exit(1)
}
do {
    try png.write(to: URL(fileURLWithPath: arguments[2]))
} catch {
    FileHandle.standardError.write(Data("cannot write \(arguments[2]): \(error)\n".utf8))
    exit(1)
}
