import XCTest
final class LoginUITests: XCTestCase {
  func testLogin() { let app = XCUIApplication(); app.launch(); sleep(3); app.buttons["Log In Now"].tap() }
}
