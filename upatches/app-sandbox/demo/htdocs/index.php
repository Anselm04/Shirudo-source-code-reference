<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// The site: says what PHP made of a request.
header('Content-Type: text/plain');
printf("%s get=%d post=%d\n", $_SERVER['REQUEST_METHOD'], count($_GET),
       count($_POST));
