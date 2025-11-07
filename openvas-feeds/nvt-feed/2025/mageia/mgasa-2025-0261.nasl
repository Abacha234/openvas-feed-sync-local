# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0261");
  script_cve_id("CVE-2025-2784", "CVE-2025-32049", "CVE-2025-32050", "CVE-2025-32051", "CVE-2025-32052", "CVE-2025-32053", "CVE-2025-32906", "CVE-2025-32907", "CVE-2025-32908", "CVE-2025-32909", "CVE-2025-32910", "CVE-2025-32911", "CVE-2025-32912", "CVE-2025-32913", "CVE-2025-32914");
  script_tag(name:"creation_date", value:"2025-11-06 04:12:34 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0261)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0261");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0261.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34187");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/53THXHSDPP4TLMFRSP5DPLY4DK72M7XY/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/EPLHUVQI4JICGWTVGG7KI7D4BMHB34YD/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/NK7USYFSJPRTIVISSEDBLS53JCM5ETOI/");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2025/04/18/4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7432-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7543-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup, libsoup3' package(s) announced via the MGASA-2025-0261 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libsoup: heap buffer over-read in `skip_insignificant_space` when
sniffing content. (CVE-2025-2784)
Libsoup: denial of service attack to websocket server. (CVE-2025-32049)
Libsoup: integer overflow in append_param_quoted. (CVE-2025-32050)
Libsoup: segmentation fault when parsing malformed data uri.
(CVE-2025-32051)
Libsoup: heap buffer overflow in sniff_unknown(). (CVE-2025-32052)
Libsoup: heap buffer overflows in sniff_feed_or_html() and
skip_insignificant_space(). (CVE-2025-32053)
Libsoup: out of bounds reads in soup_headers_parse_request().
(CVE-2025-32906)
Libsoup: denial of service in server when client requests a large amount
of overlapping ranges with range header. (CVE-2025-32907)
Libsoup: denial of service on libsoup through http/2 server.
(CVE-2025-32908)
Libsoup: null pointer dereference on libsoup through function
'sniff_mp4' in soup-content-sniffer.c. (CVE-2025-32909)
Libsoup: null pointer deference on libsoup via /auth/soup-auth-digest.c
through 'soup_auth_digest_authenticate' on client when server omits the
'realm' parameter in an unauthorized response with digest
authentication. (CVE-2025-32910)
Libsoup: double free on soup_message_headers_get_content_disposition()
through 'soup-message-headers.c' via 'params' ghashtable value.
(CVE-2025-32911)
Libsoup: null pointer dereference in client when server omits the
'nonce' parameter in an unauthorized response with digest
authentication. (CVE-2025-32912)
Libsoup: null pointer dereference in
soup_message_headers_get_content_disposition when 'filename' parameter
is present, but has no value in content-disposition header.
(CVE-2025-32913)
Libsoup: oob read on libsoup through function
'soup_multipart_new_from_message' in soup-multipart.c leads to crash or
exit of process. (CVE-2025-32914)
Libsoup: memory leak on soup_header_parse_quality_list() via
soup-headers.c. (CVE-2025-46420)
Libsoup: information disclosure may leads libsoup client sends
authorization header to a different host when being redirected by a
server. (CVE-2025-46421)
Libsoup: null pointer dereference in libsoup may lead to denial of
service. (CVE-2025-4476)
Libsoup: integer overflow in cookie expiration date handling in libsoup.
(CVE-2025-4945)");

  script_tag(name:"affected", value:"'libsoup, libsoup3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-devel", rpm:"lib64soup-devel~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-gir2.4", rpm:"lib64soup-gir2.4~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-gir3.0", rpm:"lib64soup-gir3.0~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup2.4_1", rpm:"lib64soup2.4_1~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup3-devel", rpm:"lib64soup3-devel~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup3.0_0", rpm:"lib64soup3.0_0~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-gir2.4", rpm:"libsoup-gir2.4~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-gir3.0", rpm:"libsoup-gir3.0~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-i18n", rpm:"libsoup-i18n~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2.4_1", rpm:"libsoup2.4_1~2.74.3~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3", rpm:"libsoup3~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3-devel", rpm:"libsoup3-devel~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3-i18n", rpm:"libsoup3-i18n~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3.0_0", rpm:"libsoup3.0_0~3.4.2~1.2.mga9", rls:"MAGEIA9"))) {
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
