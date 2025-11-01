# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887247");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-24789");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:58:22 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:08:59 +0000 (Wed, 19 Jun 2024)");
  script_name("Fedora: Security Advisory for kitty (FEDORA-2024-15039ba9f9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-15039ba9f9");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U5YAEIA6IUHUNGJ7AIXXPQT6D2GYENX7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kitty'
  package(s) announced via the FEDORA-2024-15039ba9f9 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Offloads rendering to the GPU for lower system load and buttery smooth
  scrolling. Uses threaded rendering to minimize input latency.

  - Supports all modern terminal features: graphics (images), unicode, true-color,
  OpenType ligatures, mouse protocol, focus tracking, bracketed paste and
  several new terminal protocol extensions.

  - Supports tiling multiple terminal windows side by side in different layouts
  without needing to use an extra program like tmux.

  - Can be controlled from scripts or the shell prompt, even over SSH.

  - Has a framework for Kittens, small terminal programs that can be used to
  extend kitty&#39,s functionality. For example, they are used for Unicode input,
  Hints and Side-by-side diff.

  - Supports startup sessions which allow you to specify the window/tab layout,
  working directories and programs to run on startup.

  - Cross-platform: kitty works on Linux and macOS, but because it uses only
  OpenGL for rendering, it should be trivial to port to other Unix-like
  platforms.

  - Allows you to open the scrollback buffer in a separate window using arbitrary
  programs of your choice. This is useful for browsing the history comfortably
  in a pager or editor.

  - Has multiple copy/paste buffers, like vim.");

  script_tag(name:"affected", value:"'kitty' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
