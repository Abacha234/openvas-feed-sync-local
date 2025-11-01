# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56143");
  script_cve_id("CVE-2005-2475");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-903)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-903");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-903");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unzip' package(s) announced via the DSA-903 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The unzip update in DSA 903 contained a regression so that symbolic links that are resolved later in a zip archive aren't supported anymore. This update corrects this behaviour. For completeness, below please find the original advisory text:

Imran Ghory discovered a race condition in the permissions setting code in unzip. When decompressing a file in a directory an attacker has access to, unzip could be tricked to set the file permissions to a different file the user has permissions to.

For the old stable distribution (woody) this problem has been fixed in version 5.50-1woody5.

For the stable distribution (sarge) this problem has been fixed in version 5.52-1sarge3.

For the unstable distribution (sid) this problem has been fixed in version 5.52-6.

We recommend that you upgrade your unzip package.");

  script_tag(name:"affected", value:"'unzip' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);