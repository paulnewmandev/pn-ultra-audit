import CoreLocation
public class LocationService { let m = CLLocationManager(); public func start() { m.requestWhenInUseAuthorization() } }
