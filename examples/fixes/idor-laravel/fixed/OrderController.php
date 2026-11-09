<?php
$order = $request->user()->orders()->findOrFail($request->id);
