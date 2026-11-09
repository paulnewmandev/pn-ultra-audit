<?php
class UserController {
  public function show() {
    $id = $_GET['id'];
    $r = DB::select("SELECT * FROM users WHERE id = " . $id);
    echo "Hello " . $_GET['name'];
    $u = User::findOrFail($request->id);
    User::create($request->all());
    if ($password == $stored) { return true; }
    system("convert " . $_GET['f']);
  }
}
