#! /usr/bin/perl -w
use strict;
use CGI;
use CGI::Carp qw/fatalsToBrowser warningsToBrowser/;
use CGI::Session ('-ip_match');

my $session = CGI::Session->load(undef,undef,{Directory=>'./tmp/sessions'});
my $q = new CGI;

print $q->header(-cache_control=>"no-cache, no-store, must-revalidate");
print $q->start_html(-title=>"Necto Control");
print $q->h1("Necto Control Center");

if($session->is_expired){
    print $q->p("Your session has expired.");

    print $q->start_form(-method=>"post", -action=>"./session.cgi");
    print $q->p("Username :"), $q->textfield(-name=>"usr",-type=>"text");
    print $q->p("Password :"), $q->password_field(-name=>"pwd",-type=>"password");
    print $q->submit(-name=>"submit");
    print $q->end_form;
}
elsif($session->is_empty){
    print $q->p("Please Log In.");


    print $q->start_form(-method=>"post", -action=>"./session.cgi");
    print $q->p("Username :"), $q->textfield(-name=>"usr",-type=>"text");
    print $q->p("Password :"), $q->password_field(-name=>"pwd",-type=>"password");
    print $q->submit(-name=>"submit");
    print $q->end_form;
}
else{
    my $fullname = $session->param('fullname');

    print $q->p("Welcome back $fullname ! ");
    print $q->a({href=>"./session.cgi?action=logout"},"Logout");
}
print $q->end_html;
