# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856881");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-12-25 05:00:23 +0000 (Wed, 25 Dec 2024)");
  script_name("openSUSE: Security Advisory for vhostmd (SUSE-SU-2024:4416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4416-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4PERHBG5MRWO3BYL4CPJHEM6BOVWX5RA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vhostmd'
  package(s) announced via the SUSE-SU-2024:4416-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vhostmd fixes the following issues:

  Updated to version 1.2

  * Fix actions using the 'free' command

  * Fix buffer accounting when generating metric XML

  * Change actions to retrieve vendor and product info

  * Add a 'unit' attribute to the metrics element

  * vif-stats.py: convert to Python3

  * conf: Update the 'VirtualizationVendor' action to strip any URLs that may
      follow the vendor name (bsc#1230961)

  * Fix virtio transport to work with libvirt >= 9.7.0

  * Added hardening to systemd service (bsc#1181400)

  * spec: Don't replace user-modified dtd in /etc/vhostmd/ (bsc#1154838)

  * Relax virtio requirement in config file (bsc#1152803)

  Updated to version 1.1 (bsc#1129772)

  * Merge libserialclient with libmetrics

  * Misc bug fixes and improvements");

  script_tag(name:"affected", value:"'vhostmd' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
