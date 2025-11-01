# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892262");
  script_cve_id("CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13765", "CVE-2020-1983");
  script_tag(name:"creation_date", value:"2020-06-30 03:00:09 +0000 (Tue, 30 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 20:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Debian: Security Advisory (DLA-2262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2262");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2262");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-2262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in qemu, a fast processor emulator.

CVE-2020-1983

slirp: Fix use-after-free in ip_reass().

CVE-2020-13361

es1370_transfer_audio in hw/audio/es1370.c allowed guest OS users to trigger an out-of-bounds access during an es1370_write() operation.

CVE-2020-13362

megasas_lookup_frame in hw/scsi/megasas.c had an out-of-bounds read via a crafted reply_queue_head field from a guest OS user.

CVE-2020-13765

hw/core/loader: Fix possible crash in rom_copy().

For Debian 8 Jessie, these problems have been fixed in version 1:2.1+dfsg-12+deb8u15.

We recommend that you upgrade your qemu packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);