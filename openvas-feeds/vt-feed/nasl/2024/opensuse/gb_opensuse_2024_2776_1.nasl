# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856363");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31083");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-05 12:15:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:05:32 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for dri3proto, presentproto, wayland (SUSE-SU-2024:2776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2776-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4RMRHO75RRQX45LWSKFMSGADTLHE7KZD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dri3proto, presentproto, wayland'
  package(s) announced via the SUSE-SU-2024:2776-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dri3proto, presentproto, wayland-protocols, xwayland fixes the
  following issues:

  Changes in presentproto:

  * update to version 1.4 (patch generated from xorgproto-2024.1 sources)

  Changes in wayland-protocols:

  * Update to version 1.36:

  * xdg-dialog: fix missing namespace in protocol name

  * Changes from version 1.35:

  * cursor-shape-v1: Does not advertises the list of supported cursors

  * xdg-shell: add missing enum attribute to set_constraint_adjustment

  * xdg-shell: recommend against drawing decorations when tiled

  * tablet-v2: mark as stable

  * staging: add alpha-modifier protocol

  * Update to 1.36

  * Fix to the xdg dialog protocol

  * tablet-v2 protocol is now stable

  * alpha-modifier: new protocol

  * Bug fix to the cursor shape documentation

  * The xdg-shell protocol now also explicitly recommends against drawing
      decorations outside of the window geometry when tiled

  * Update to 1.34:

  * xdg-dialog: new protocol

  * xdg-toplevel-drag: new protocol

  * Fix typo in ext-foreign-toplevel-list-v1

  * tablet-v2: clarify that name/id events are optional

  * linux-drm-syncobj-v1: new protocol

  * linux-explicit-synchronization-v1: add linux-drm-syncobj note

  * Update to version 1.33:

  * xdg-shell: Clarify what a toplevel by default includes

  * linux-dmabuf: sync changes from unstable to stable

  * linux-dmabuf: require all planes to use the same modifier

  * presentation-time: stop referring to Linux/glibc

  * security-context-v1: Make sandbox engine names use reverse-DNS

  * xdg-decoration: remove ambiguous wording in configure event

  * xdg-decoration: fix configure event summary

  * linux-dmabuf: mark as stable

  * linux-dmabuf: add note about implicit sync

  * security-context-v1: Document what can be done with the open sockets

  * security-context-v1: Document out of band metadata for flatpak

  Changes in dri3proto:

  * update to version 1.4 (patch generated from xorgproto-2024.1 sources)

  Changes in xwayland:

  * Update to bugfix release 24.1.1 for the current stable 24.1 branch of
      Xwayland

  * xwayland: fix segment fault in `xwl_glamor_gbm_init_main_dev`

  * os: Explicitly include X11/Xmd.h for CARD32 definition to fix building on
      i686

  * present: On *BSD, epoll-shim is needed to emulate eventfd()

  * xwayland: Stop on first unmapped child

  * xwayland/window-buffers: Promote xwl_window_buffer

  * xwayland/window-buffers: Add xwl_window_buffer_release()

  * xwayland/g ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'dri3proto, presentproto, wayland' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
