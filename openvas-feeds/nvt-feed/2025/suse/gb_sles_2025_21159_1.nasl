# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21159.1");
  script_cve_id("CVE-2025-30189");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521159-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252839");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023506.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot24' package(s) announced via the SUSE-SU-2025:21159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot24 fixes the following issues:

- Update dovecot to 2.4.2:
 - CVE-2025-30189: Fixed users cached with same cache key when
 auth cache was enabled (bsc#1252839)
 - Changes
 - auth: Remove proxy_always field.
 - config: Change settings history parsing to use python3.
 - doveadm: Print table formatter - Print empty values as '-'.
 - imapc: Propagate remote error codes properly.
 - lda: Default mail_home=$HOME environment if not using userdb
 lookup
 - lib-dcrypt: Salt for new version 2 keys has been increased to
 16 bytes.
 - lib-dregex: Add libpcre2 based regular expression support to
 Dovecot, if the library is missing, disable all regular
 expressions. This adds libpcre2-32 as build dependency.
 - lib-oauth2: jwt - Allow nbf and iat to point 1 second into
 future.
 - lib: Replace libicu with our own unicode library. Removes
 libicu as build dependency.
 - login-common: If proxying fails due to remote having invalid
 SSL cert, don't reconnect.
 - New features
 - auth: Add ssl_client_cert_fp and ssl_client_cert_pubkey_fp
 fields
 - config: Add support for $SET:filter/path/setting.
 - config: Improve @group includes to work with overwriting
 their settings.
 - doveadm kick: Add support for kicking multiple usernames
 - doveadm mailbox status: Add support for deleted status item.
 - imap, imap-client: Add experimental partial IMAP4rev2
 support.
 - imap: Implement support for UTF8=ACCEPT for APPEND
 - lib-oauth2, oauth2: Add oauth2_token_expire_grace setting.
 - lmtp: lmtp-client - Support command pipelining.
 - login-common: Support local/remote blocks better.
 - master: accept() unix/inet connections before creating child
 process to handle it. This reduces timeouts when child
 processes are slow to spawn themselves.
 - Bug fixes
 - SMTPUTF8 was accepted even when it wasn't enabled.
 - auth, *-login: Direct logging with -L parameter was not
 working.
 - auth: Crash occurred when OAUTH token validation failed with
 oauth2_use_worker_with_mech=yes.
 - auth: Invalid field handling crashes were fixed.
 - auth: ldap - Potential crash could happen at deinit.
 - auth: mech-gssapi - Server sending empty initial response
 would cause errors.
 - auth: mech-winbind - GSS-SPNEGO mechanism was erroneously
 marked as
 - not accepting NUL.
 - config: Multiple issues with $SET handling has been fixed.
 - configure: Building without LDAP didn't work.
 - doveadm: If source user didn't exist, a crash would occur.
 - imap, pop3, submission, imap-urlauth: USER environment usage
 was broken when running standalone.
 - imap-hibernate: Statistics would get truncated on
 unhibernation.
 - imap: 'SEARCH MIMEPART FILENAME ENDS' command could have
 accessed memory outside allocated buffer, resulting in a
 crash.
 - imapc: Fetching partial headers would cause other cached
 headers to be cached empty, breaking e.g. imap envelope
 responses when caching to disk.
 - imapc: Shared ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dovecot24' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot24", rpm:"dovecot24~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-backend-mysql", rpm:"dovecot24-backend-mysql~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-backend-pgsql", rpm:"dovecot24-backend-pgsql~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-backend-sqlite", rpm:"dovecot24-backend-sqlite~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-devel", rpm:"dovecot24-devel~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-fts", rpm:"dovecot24-fts~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot24-fts-solr", rpm:"dovecot24-fts-solr~2.4.2~160000.1.1", rls:"SLES16.0.0"))) {
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
