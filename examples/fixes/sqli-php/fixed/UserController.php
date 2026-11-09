<?php
$id = $_GET['id'];
$rows = DB::select("select * from users where id = ?", [$id]);
