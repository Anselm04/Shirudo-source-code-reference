/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

(function () {
	"use strict";

	var chevron = '<svg viewBox="0 0 10 10" aria-hidden="true">' +
		'<path d="M3 1.5 6.5 5 3 8.5" fill="none" stroke="currentColor" ' +
		'stroke-width="1.5"/></svg>';

	function tree() {
		var root = document.querySelector(".tree");
		var opened = false;

		if (!root)
			return;
		root.querySelectorAll("li").forEach(function (li) {
			var sub = li.querySelector(":scope > ul");
			var link = li.querySelector(":scope > a");
			var button;

			if (!sub || !link)
				return;
			button = document.createElement("button");
			button.type = "button";
			button.className = "chev";
			button.innerHTML = chevron;
			button.setAttribute("aria-label", "Expand " + link.textContent);
			li.insertBefore(button, sub);
			if (li.classList.contains("current")) {
				li.classList.add("open");
				opened = true;
			}
			button.setAttribute("aria-expanded",
					    String(li.classList.contains("open")));
			button.addEventListener("click", function () {
				var open = li.classList.toggle("open");

				button.setAttribute("aria-expanded", String(open));
			});
		});
		if (!opened) {
			var first = root.querySelector(".toctree-l1");

			if (first && first.querySelector(":scope > ul")) {
				first.classList.add("open");
				first.querySelector(":scope > .chev")
					.setAttribute("aria-expanded", "true");
			}
		}
	}

	function menu() {
		var side = document.querySelector(".side");
		var button = document.querySelector(".menu-toggle");

		if (!side || !button)
			return;
		button.addEventListener("click", function () {
			var open = side.classList.toggle("open");

			button.setAttribute("aria-expanded", String(open));
		});
	}

	/* The command a block shows, without its prompts and output. */
	function command(pre) {
		var parts = [];

		if (!pre.querySelector(".gp"))
			return pre.textContent;
		pre.childNodes.forEach(function (node) {
			if (node.nodeType === 1 &&
			    (node.classList.contains("gp") ||
			     node.classList.contains("go")))
				return;
			parts.push(node.textContent);
		});
		return parts.join("").replace(/^\s+$/gm, "").replace(/\n{2,}/g, "\n");
	}

	function code() {
		document.querySelectorAll("div.highlight").forEach(function (block) {
			var pre = block.querySelector("pre");
			var button = document.createElement("button");

			if (!pre)
				return;
			pre.querySelectorAll(".gp").forEach(function (prompt) {
				if (prompt.textContent.indexOf("operator$") === 0)
					prompt.classList.add("op");
				else if (prompt.textContent.indexOf("target#") === 0)
					prompt.classList.add("tg");
			});
			button.type = "button";
			button.className = "copy";
			button.textContent = "Copy";
			button.addEventListener("click", function () {
				var done = function (label) {
					button.textContent = label;
					setTimeout(function () {
						button.textContent = "Copy";
					}, 1400);
				};
				var select = function () {
					var range = document.createRange();
					var selection = window.getSelection();

					range.selectNodeContents(pre);
					selection.removeAllRanges();
					selection.addRange(range);
					done("Selected");
				};

				if (!navigator.clipboard) {
					select();
					return;
				}
				navigator.clipboard.writeText(command(pre)).then(
					function () { done("Copied"); }, select);
			});
			block.appendChild(button);
		});
	}

	function spy() {
		var links = document.querySelectorAll(".toc > ul > li > ul > li > a");
		var targets = [];
		var observer;

		links.forEach(function (link) {
			var id = decodeURIComponent(link.hash.slice(1));
			var target = id && document.getElementById(id);

			if (target)
				targets.push({ link: link, target: target });
		});
		if (!targets.length || !("IntersectionObserver" in window))
			return;
		observer = new IntersectionObserver(function (entries) {
			entries.forEach(function (entry) {
				if (!entry.isIntersecting)
					return;
				targets.forEach(function (t) {
					t.link.classList.toggle("on",
							       t.target === entry.target);
				});
			});
		}, { rootMargin: "-70px 0px -70% 0px" });
		targets.forEach(function (t) { observer.observe(t.target); });
	}

	function search() {
		var input = document.querySelector(".search input");

		if (!input)
			return;
		document.addEventListener("keydown", function (event) {
			var active = document.activeElement;

			if (event.key !== "/" || active === input ||
			    /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName))
				return;
			event.preventDefault();
			input.focus();
		});
	}

	/*
	 * An explicit choice overrides the system preference and is kept per
	 * browser; storage can be unavailable, in which case it lasts the page.
	 */
	function theme() {
		var button = document.querySelector(".theme-toggle");
		var root = document.documentElement;
		var media = window.matchMedia("(prefers-color-scheme: dark)");

		if (!button)
			return;
		var current = function () {
			return root.getAttribute("data-theme") ||
			       (media.matches ? "dark" : "light");
		};
		var label = function () {
			var next = current() === "dark" ? "light" : "dark";

			button.textContent = next === "dark" ? "Dark" : "Light";
			button.setAttribute("aria-label", "Switch to the " + next +
					    " theme");
		};
		button.addEventListener("click", function () {
			var next = current() === "dark" ? "light" : "dark";

			root.setAttribute("data-theme", next);
			try {
				localStorage.setItem("shirudo-theme", next);
			} catch (e) {
				/* the choice then lasts until the page is left */
			}
			label();
		});
		media.addEventListener("change", label);
		label();
		button.hidden = false;
	}

	document.addEventListener("DOMContentLoaded", function () {
		tree();
		menu();
		code();
		spy();
		search();
		theme();
	});
})();
