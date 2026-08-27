#!/usr/bin/env swift
//
// Ставит иконку-щит на директорию.
//
// Лежит в репозитории, а не выполняется руками один раз: иначе иконка исчезнет
// при первой же переустановке и никто не вспомнит, как её вернуть.
//
//   swift tools/set-icon.swift /path/to/dir

import AppKit

let args = CommandLine.arguments
guard args.count > 1 else {
    FileHandle.standardError.write("укажи путь к директории\n".data(using: .utf8)!)
    exit(1)
}
let target = args[1]

var isDir: ObjCBool = false
guard FileManager.default.fileExists(atPath: target, isDirectory: &isDir), isDir.boolValue else {
    FileHandle.standardError.write("не директория: \(target)\n".data(using: .utf8)!)
    exit(1)
}

let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)
image.lockFocus()

// Щит: скруглённый верх, сходящийся книзу клин.
let w = size.width, h = size.height
let shield = NSBezierPath()
let top = h * 0.94, bottom = h * 0.06
let halfW = w * 0.34, cx = w / 2

shield.move(to: NSPoint(x: cx, y: bottom))
shield.curve(to: NSPoint(x: cx - halfW, y: top * 0.72),
             controlPoint1: NSPoint(x: cx - halfW * 0.75, y: bottom + h * 0.16),
             controlPoint2: NSPoint(x: cx - halfW, y: h * 0.42))
shield.line(to: NSPoint(x: cx - halfW, y: top - h * 0.10))
shield.curve(to: NSPoint(x: cx, y: top),
             controlPoint1: NSPoint(x: cx - halfW, y: top),
             controlPoint2: NSPoint(x: cx - halfW * 0.45, y: top))
shield.curve(to: NSPoint(x: cx + halfW, y: top - h * 0.10),
             controlPoint1: NSPoint(x: cx + halfW * 0.45, y: top),
             controlPoint2: NSPoint(x: cx + halfW, y: top))
shield.line(to: NSPoint(x: cx + halfW, y: top * 0.72))
shield.curve(to: NSPoint(x: cx, y: bottom),
             controlPoint1: NSPoint(x: cx + halfW, y: h * 0.42),
             controlPoint2: NSPoint(x: cx + halfW * 0.75, y: bottom + h * 0.16))
shield.close()

let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.30, green: 0.58, blue: 0.98, alpha: 1.0),
    NSColor(calibratedRed: 0.11, green: 0.29, blue: 0.72, alpha: 1.0),
])!
gradient.draw(in: shield, angle: -90)

NSColor(calibratedWhite: 1.0, alpha: 0.55).setStroke()
shield.lineWidth = w * 0.022
shield.stroke()

// Галка внутри щита — «проверено», а не «запрещено»: движок пропускает работу,
// пока правило не нарушено.
let check = NSBezierPath()
check.move(to: NSPoint(x: cx - w * 0.155, y: h * 0.505))
check.line(to: NSPoint(x: cx - w * 0.035, y: h * 0.375))
check.line(to: NSPoint(x: cx + w * 0.175, y: h * 0.655))
check.lineWidth = w * 0.075
check.lineCapStyle = .round
check.lineJoinStyle = .round
NSColor.white.setStroke()
check.stroke()

image.unlockFocus()

if NSWorkspace.shared.setIcon(image, forFile: target, options: []) {
    print("🛡  иконка установлена: \(target)")
} else {
    FileHandle.standardError.write("не удалось установить иконку\n".data(using: .utf8)!)
    exit(1)
}
