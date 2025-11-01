# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892432");
  script_cve_id("CVE-2018-19351", "CVE-2018-21030", "CVE-2018-8768");
  script_tag(name:"creation_date", value:"2020-11-20 04:00:21 +0000 (Fri, 20 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-19 07:15:00 +0000 (Thu, 19 Nov 2020)");

  script_name("Debian: Security Advisory (DLA-2432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2432");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2432");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jupyter-notebook");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jupyter-notebook' package(s) announced via the DLA-2432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in jupyter-notebook.

CVE-2018-8768

A maliciously forged notebook file can bypass sanitization to execute Javascript in the notebook context. Specifically, invalid HTML is fixed by jQuery after sanitization, making it dangerous.

CVE-2018-19351

allows XSS via an untrusted notebook because nbconvert responses are considered to have the same origin as the notebook server.

CVE-2018-21030

jupyter-notebook does not use a CSP header to treat served files as belonging to a separate origin. Thus, for example, an XSS payload can be placed in an SVG document.

For Debian 9 stretch, these problems have been fixed in version 4.2.3-4+deb9u1.

We recommend that you upgrade your jupyter-notebook packages.

For the detailed security status of jupyter-notebook please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'jupyter-notebook' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);