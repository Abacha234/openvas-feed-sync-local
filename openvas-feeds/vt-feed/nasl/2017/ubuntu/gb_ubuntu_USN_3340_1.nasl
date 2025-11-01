# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843226");
  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679");
  script_tag(name:"creation_date", value:"2017-06-27 04:59:33 +0000 (Tue, 27 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-3340-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3340-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3340-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-3340-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanuel Dreyfus discovered that third-party modules using the
ap_get_basic_auth_pw() function outside of the authentication phase may
lead to authentication requirements being bypassed. This update adds a new
ap_get_basic_auth_components() function for use by third-party modules.
(CVE-2017-3167)

Vasileios Panopoulos discovered that the Apache mod_ssl module may crash
when third-party modules call ap_hook_process_connection() during an HTTP
request to an HTTPS port. (CVE-2017-3169)

Javier Jimenez discovered that the Apache HTTP Server incorrectly handled
parsing certain requests. A remote attacker could possibly use this issue
to cause the Apache HTTP Server to crash, resulting in a denial of service.
(CVE-2017-7668)

ChenQin and Hanno Bock discovered that the Apache mod_mime module
incorrectly handled certain Content-Type response headers. A remote
attacker could possibly use this issue to cause the Apache HTTP Server to
crash, resulting in a denial of service. (CVE-2017-7679)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
