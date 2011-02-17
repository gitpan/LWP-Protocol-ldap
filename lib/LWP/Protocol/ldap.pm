# Copyright (c) 1998-2004 Graham Barr <gbarr@pobox.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package LWP::Protocol::ldap;

use warnings;
use strict;

use Carp ();

use HTTP::Status ();
use HTTP::Negotiate ();
use HTTP::Response ();
use LWP::MediaTypes ();
require LWP::Protocol;

our @ISA = qw(LWP::Protocol);

=head1 NAME

LWP::Protocol::ldap - The great new LWP::Protocol::ldap!

=head1 VERSION

Version 1.12

=cut

our $VERSION = '1.12';

eval {
  require Net::LDAP;
};
my $init_failed = $@ ? $@ : undef;


=head1 SYNOPSIS

This module is another version of the great original Graham Barr Module ldap.pm
It is used for supply to the LWP::userAgent an access to LDAP services like the command "ldapsearch".
The authentification user/password work. 
Formating Export data is ldif or html (default)

# do the work for you
use LWP::UserAgent;
use LWP::Protocol;
use LWP::Protocol::ldap;

LWP::Protocol::implementor('ldap',  'LWP::Protocol::ldap');

# now just continue as normal
my $ua = new LWP::UserAgent;
$ua->default_header( 'Accept' => 'text/ldif' );
my $response = $ua->get('ldap://user:passord@ldap.server:389/dn=com?attributSearch?one?(objectclass=*)');
my $html = $res->content();
print $html;


or if there is no authentification

my $ua = new LWP::UserAgent;
my $response = $ua->get('ldap://ldap.server/dn=com?attributSearch?one?(objectclass=*)?x-format=ldif');
my $html = $res->content();
print $html;

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 request

=cut

sub request {
  my($self, $request, $proxy, $arg, $size, $timeout) = @_;

  $size = 4096 unless $size;

  LWP::Debug::trace('()') if defined &LWP::Debug::trace;

  # check proxy
  if (defined $proxy)
  {
    return new HTTP::Response &HTTP::Status::RC_BAD_REQUEST,
                 'You can not proxy through the ldap';
  }

  my $url = $request->url;
  if ($url->scheme ne 'ldap') {
    my $scheme = $url->scheme;
    return new HTTP::Response &HTTP::Status::RC_INTERNAL_SERVER_ERROR,
            "LWP::Protocol::ldap::request called for '$scheme'";
  }

  # check method
  my $method = $request->method;

#  unless ($method eq 'GET') {
#    return new HTTP::Response &HTTP::Status::RC_BAD_REQUEST,
#                 'Library does not allow method ' .
#                 "$method for 'ldap:' URLs";
#  }

  if ($init_failed) {
    return new HTTP::Response &HTTP::Status::RC_INTERNAL_SERVER_ERROR,
            $init_failed;
  }

  my $host     = $url->host;
  my $port     = $url->port;
  my $userinfo = $url->userinfo;
  my ($user, $password) = defined($userinfo) ? split(":", $userinfo, 2) : ();

  # Create an initial response object
  my $response = new HTTP::Response &HTTP::Status::RC_OK, "Document follows";
  $response->request($request);

  my $ldap = new Net::LDAP($host, port => $port);

  my $mesg;
  if ($user) {
    $mesg = $ldap->bind($user, password => $password);
  }
  else {
    $mesg = $ldap->bind();
  }

  if ((defined $mesg->{'resultCode'}) && ($mesg->{'resultCode'} ne 0)) {
    my $res = new HTTP::Response &HTTP::Status::RC_UNAUTHORIZED, 
        "LDAP return code " . $mesg->{'resultCode'};
    $res->content_type("text/plain");
    $res->content($mesg->{'errorMessage'});
    return $res; 
  }

  my $dn = $url->dn;
  my @attrs = $url->attributes;
  my $scope = $url->scope || "base";
  my $filter = $url->filter;
  my @opts = (scope => $scope);
  my %extn = $url->extensions;

  my $format = lc($extn{'x-format'} || 'html');

  if (my $accept = $request->header('Accept')) {
    $format = 'ldif' if $accept =~ m!\btext/ldif\b!;
  }
  
  push @opts, "base" => $dn if $dn;
  push @opts, "filter" => $filter if $filter;
  push @opts, "attrs" => \@attrs if @attrs;

  $mesg = $ldap->search(@opts);
  if ((defined $mesg->{'resultCode'}) && ($mesg->{'resultCode'} ne 0)) {
    my $res = new HTTP::Response &HTTP::Status::RC_BAD_REQUEST,
         "LDAP return code " . $mesg->{'resultCode'};
    $res->content_type("text/plain");
    $res->content($mesg->{'errorMessage'});
    return $res;
  }
  elsif ($format eq 'ldif') {
    require Net::LDAP::LDIF;
    open(my $fh, ">", \my $content);
    my $ldif = Net::LDAP::LDIF->new($fh,"w", version => 1);
    while(my $entry = $mesg->shift_entry) {
      $ldif->write_entry($entry);
    }
    $ldif->done;
    close($fh);
    $response->header('Content-Type' => 'text/ldif');
    $response->header('Content-Length', length($content));
    $response = $self->collect_once($arg, $response, $content)
	if ($method ne 'HEAD');
  }
  else {
    my $content = "<html><head><title>Directory Search Results</title></head>\n<body>";
    my $entry;
    my $index;

    for($index = 0 ; $entry = $mesg->entry($index) ; $index++ ) {
      my $attr;

      $content .= $index ? qq{<tr><th colspan="2"><hr>&nbsp</tr>\n} : "<table>";

      $content .= qq{<tr><th colspan="2">} . $entry->dn . "</th></tr>\n";

      foreach $attr ($entry->attributes) {
        my $vals = $entry->get_value($attr, asref => 1);
        my $val;

        $content .= q{<tr><td align="right" valign="top"};
        $content .= q{ rowspan="} . scalar(@$vals) . q{"}
          if (@$vals > 1);
        $content .= ">" . $attr  . "&nbsp</td>\n";

        my $j = 0;
        foreach $val (@$vals) {
	  $val = qq!<a href="$val">$val</a>! if $val =~ /^https?:/;
	  $val = qq!<a href="mailto:$val">$val</a>! if $val =~ /^[-\w]+\@[-.\w]+$/;
          $content .= "<tr>" if $j++;
          $content .= "<td>" . $val . "</td></tr>\n";
        }
      }
    }

    $content .= "</table>" if $index;
    $content .= "<hr>";
    $content .= $index ? sprintf("%s Match%s found",$index, $index>1 ? "es" : "")
		       : "<b>No Matches found</b>";
    $content .= "</body></html>\n";
    $response->header('Content-Type' => 'text/html');
    $response->header('Content-Length', length($content));
    $response = $self->collect_once($arg, $response, $content)
	if ($method ne 'HEAD');

  }

  $ldap->unbind;

  $response;
}


=head1 AUTHOR

Jef Le_Ponot, C<< <jef_le_ponot at voila.fr> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-lwp-protocol-ldap at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=LWP-Protocol-ldap>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc LWP::Protocol::ldap


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=LWP-Protocol-ldap>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/LWP-Protocol-ldap>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/LWP-Protocol-ldap>

=item * Search CPAN

L<http://search.cpan.org/dist/LWP-Protocol-ldap/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Jef Le_Ponot.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of LWP::Protocol::ldap
