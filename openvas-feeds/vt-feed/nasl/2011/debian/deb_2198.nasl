# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69334");
  script_cve_id("CVE-2011-1400");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2198");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2198");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tex-common' package(s) announced via the DSA-2198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Svensson discovered that tex-common, a package shipping a number of scripts and configuration files necessary for TeX, contains insecure settings for the shell_escape_commands directive. Depending on the scenario, this may result in arbitrary code execution when a victim is tricked into processing a malicious tex-file or this is done in an automated fashion.

The oldstable distribution (lenny) is not affected by this problem due to shell_escape being disabled.

For the stable distribution (squeeze), this problem has been fixed in version 2.08.1.

For the testing (wheezy) and unstable (sid) distributions, this problem will be fixed soon.

We recommend that you upgrade your tex-common packages.");

  script_tag(name:"affected", value:"'tex-common' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);