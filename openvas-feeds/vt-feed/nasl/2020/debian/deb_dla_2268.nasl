# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892268");
  script_cve_id("CVE-2020-14093", "CVE-2020-14954");
  script_tag(name:"creation_date", value:"2020-07-01 03:02:41 +0000 (Wed, 01 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-2268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2268");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2268-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DLA-2268 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in mutt, a console email client.

CVE-2020-14093

Mutt allowed an IMAP fcc/postpone man-in-the-middle attack via a PREAUTH response.

CVE-2020-14954

Mutt had a STARTTLS buffering issue that affected IMAP, SMTP, and POP3. When a server had sent a begin TLS response, the client read additional data (e.g., from a man-in-the-middle attacker) and evaluated it in a TLS context, aka response injection.

In Debian jessie, the mutt source package builds two variants of mutt: mutt and mutt-patched.

The previous package version (1.5.23-3+deb8u2, DLA-2268-1) provided fixes for the issues referenced above, but they were only applied for the mutt-patched package build, not for the (vanilla) mutt package build.

For Debian 8 Jessie, these problems have been fixed in version 1.5.23-3+deb8u3.

We recommend that you upgrade your mutt packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);