# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892669");
  script_cve_id("CVE-2021-3541");
  script_tag(name:"creation_date", value:"2021-05-31 03:00:11 +0000 (Mon, 31 May 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 16:35:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2669)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2669");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2669");
  script_xref(name:"URL", value:"https://blog.hartwork.org/posts/cve-2021-3541-parameter-laughs-fixed-in-libxml2-2-9-11/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxml2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DLA-2669 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in libxml2, the GNOME XML library. This issue is called 'Parameter Laughs'-attack and is related to parameter entities expansion. It is similar to the 'Billion Laughs'-attacks found earlier in libexpat. More information can be found at [1]

[1] [link moved to references]

For Debian 9 stretch, this problem has been fixed in version 2.9.4+dfsg1-2.2+deb9u5.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);