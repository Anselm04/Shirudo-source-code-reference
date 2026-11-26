<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// What an attacker who runs PHP in the server tries next, and what the
// site itself must still be able to do, one line each, in uploads/.
header('Content-Type: text/plain');
$dir = __DIR__ . '/uploads';

function say($what, $ok)
{
	echo $what, ': ', $ok ? 'ok' : 'refused', "\n";
}

function put($dir, $name)
{
	say("write $name", @file_put_contents("$dir/$name", "# x\n") !== false);
}

function reach($host, $port)
{
	$s = @fsockopen($host, $port, $errno, $errstr, 2);
	echo "connect $host port $port: ", $s ? 'ok' : "errno $errno", "\n";
	if ($s)
		fclose($s);
}

// What an earlier request left.
foreach (['note.txt', 'note.php', 'shell.php', 'ran-a-command'] as $name)
	@unlink("$dir/$name");
@rmdir("$dir/d.php");

put($dir, 'note.txt');
put($dir, 'shell.php');
say('rename note.txt note.php', @rename("$dir/note.txt", "$dir/note.php"));
say('mkdir d.php', @mkdir("$dir/d.php"));
@exec('/bin/touch ' . escapeshellarg("$dir/ran-a-command"));
clearstatcache();
echo 'run a command: ',
     file_exists("$dir/ran-a-command") ? 'ran' : 'did not run', "\n";
reach('127.0.0.1', 8443);
reach($_GET['far'] ?? '1.1.1.1', 80);
