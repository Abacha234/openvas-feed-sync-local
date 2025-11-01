# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892477");
  script_cve_id("CVE-2020-26215");
  script_tag(name:"creation_date", value:"2020-12-03 04:00:09 +0000 (Thu, 03 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 15:59:00 +0000 (Thu, 03 Dec 2020)");

  script_name("Debian: Security Advisory (DLA-2477)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2477");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2477");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jupyter-notebook' package(s) announced via the DLA-2477 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in the Jupyter interactive notebook system where a maliciously-crafted link could redirect the browser to a malicious/spoofed website.

CVE-2020-26215

Jupyter Notebook before version 6.1.5 has an Open redirect vulnerability. A maliciously crafted link to a notebook server could redirect the browser to a different website. All notebook servers are technically affected, however, these maliciously crafted links can only be reasonably made for known notebook server hosts. A link to your notebook server may appear safe, but ultimately redirect to a spoofed server on the public internet. The issue is patched in version 6.1.5.

For Debian 9 Stretch, these problems have been fixed in version 4.2.3-4+deb9u2.

We recommend that you upgrade your jupyter-notebook packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jupyter-notebook' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);