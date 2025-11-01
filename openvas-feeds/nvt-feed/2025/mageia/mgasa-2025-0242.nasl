# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0242");
  script_cve_id("CVE-2025-11230");
  script_tag(name:"creation_date", value:"2025-10-23 04:08:53 +0000 (Thu, 23 Oct 2025)");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0242.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34673");
  script_xref(name:"URL", value:"https://www.haproxy.com/blog/october-2025-cve-2025-11230-haproxy-mjson-library-denial-of-service-vulnerability");
  script_xref(name:"URL", value:"https://www.haproxy.org/download/2.8/src/CHANGELOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the MGASA-2025-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Haproxy has a critical, a major, few medium and few minor bugs fixed in the
last upstream version 2.8.16 of branch 2.8.

Fixed critical bug list:
- mjson: fix possible DoS when parsing numbers

Fixed major bug list:
- listeners: transfer connection accounting when switching listeners

Fixed medium bugs list:
- check: Requeue healthchecks on I/O events to handle check timeout
- check: Set SOCKERR by default when a connection error is reported
- checks: fix ALPN inheritance from server
- dns: Reset reconnect tempo when connection is finally established
- fd: Use the provided tgid in fd_insert() to get tgroup_info
- h1: Allow reception if we have early data
- h1/h2/h3: reject forbidden chars in the Host header field
- h2/h3: reject some forbidden chars in :authority before reassembly
- hlua: Add function to change the body length of an HTTP Message
- hlua: Forbid any L6/L7 sample fetche functions from lua services
- hlua: Report to SC when data were consumed on a lua socket
- hlua: Report to SC when output data are blocked on a lua socket
- http-client: Ask for more room when request data cannot be xferred
- http-client: Don't wake http-client applet if nothing was xferred
- http-client: Drain the request if an early response is received
- http-client: Notify applet has more data to deliver until the EOM
- http-client: Properly inc input data when HTX blocks are xferred
- http-client: Test HTX_FL_EOM flag before commiting the HTX buffer
- httpclient: Throw an error if an lua httpclient instance is reused
- mux-h2: Properly handle connection error during preface sending
- server: Duplicate healthcheck's alpn inherited from default server
- ssl: ca-file directory mode must read every certificates of a file
- ssl/clienthello: ECDSA with ssl-max-ver TLSv1.2 and no ECDSA ciphers
- ssl: create the mux immediately on early data
- ssl: Fix 0rtt to the server
- ssl: fix build with AWS-LC
- threads: Disable the workaround to load libgcc_s on macOS");

  script_tag(name:"affected", value:"'haproxy' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~2.8.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-noquic", rpm:"haproxy-noquic~2.8.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-quic", rpm:"haproxy-quic~2.8.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-utils", rpm:"haproxy-utils~2.8.16~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
