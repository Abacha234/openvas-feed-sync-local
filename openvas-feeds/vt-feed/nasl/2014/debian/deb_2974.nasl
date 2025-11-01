# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702974");
  script_cve_id("CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-4721");
  script_tag(name:"creation_date", value:"2014-07-07 22:00:00 +0000 (Mon, 07 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2974)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2974");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2974");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2974 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a general-purpose scripting language commonly used for web application development. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-0207

Francisco Alonso of the Red Hat Security Response Team reported an incorrect boundary check in the cdf_read_short_sector() function.

CVE-2014-3478

Francisco Alonso of the Red Hat Security Response Team discovered a flaw in the way the truncated pascal string size in the mconvert() function is computed.

CVE-2014-3479

Francisco Alonso of the Red Hat Security Response Team reported an incorrect boundary check in the cdf_check_stream_offset() function.

CVE-2014-3480

Francisco Alonso of the Red Hat Security Response Team reported an insufficient boundary check in the cdf_count_chain() function.

CVE-2014-3487

Francisco Alonso of the Red Hat Security Response Team discovered an incorrect boundary check in the cdf_read_property_info() function.

CVE-2014-3515

Stefan Esser discovered that the ArrayObject and the SPLObjectStorage unserialize() handler do not verify the type of unserialized data before using it. A remote attacker could use this flaw to execute arbitrary code.

CVE-2014-4721

Stefan Esser discovered a type confusion issue affecting phpinfo(), which might allow an attacker to obtain sensitive information from process memory.

For the stable distribution (wheezy), these problems have been fixed in version 5.4.4-14+deb7u12. In addition, this update contains several bugfixes originally targeted for the upcoming Wheezy point release.

For the testing distribution (jessie), these problems have been fixed in version 5.6.0~rc2+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 5.6.0~rc2+dfsg-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);