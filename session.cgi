#! /usr/bin/perl -w
use strict;
use CGI;
use CGI::Session ( '-ip_match' );
use CGI::Carp qw/fatalsToBrowser warningsToBrowser/;
use Net::LDAP qw/LDAP_SUCCESS LDAP_PROTOCOL_ERROR/;
use Config::Simple;

# import configuration
my $cfg = new Config::Simple();
$cfg->read('./config/necto.cfg');

# create main cgi object
my $q = CGI->new;
my $session = CGI::Session->load(undef,undef,{Directory=>$cfg->param("session.dir")});

my $username = $q->param('usr');
my $password = $q->param('pwd');

if(($username && $password) ne ""){
    #control credential against ldap directory
    my $ldap = Net::LDAP->new($cfg->param("ldap.address"), port=>$cfg->param("ldap.port"));
    
    #bind anonymously, perform a search of the username, then rebind using the user password
    my $ldap_msg = $ldap->bind;

    unless ($ldap_msg->is_error){
        
        $ldap_msg = $ldap->search( filter=>"(uid=$username)", base=>$cfg->param("ldap.base"), scope=>$cfg->param("ldap.scope"));

        if($ldap_msg->count != 0 && !$ldap_msg->is_error){

            my @search_result = $ldap_msg->entries;
            my $user_entry = $search_result[0];
            my $user_dn = $user_entry->dn;
            # rebind using user/password
            $ldap_msg = $ldap->bind($user_dn, password=>$password);

            unless($ldap_msg->is_error){
                #login is successfull, create session and store param in session
                $session = new CGI::Session(undef,undef,{Directory=>$cfg->param("session.dir")});

                # user has to re-log in after 15m of inactivity
                $session->param(-name=>'is_logged_in', -value=>'true');
                $session->expire('is_logged_in', $cfg->param("session.ttl"));

                # store user information in session
                $session->param(-name=>'dn', -value=>$user_dn);
                $session->param(-name=>'cn', -value=>$user_entry->get_value('cn'));
                $session->param(-name=>'sn', -value=>$user_entry->get_value('sn'));
                $session->param(-name=>'mail', -value=>$user_entry->get_value('mail'));
                $session->param(-name=>'uid', -value=>$user_entry->get_value('uid'));
                $session->param(-name=>'password', -value=>$password);

                #session objects are destroyed after one hour
                $session->expire($cfg->param("session.expire"));

                print $session->header(-location=>'index.cgi');
            }
            else {
                my $error = $ldap_msg->error_text;
                print $q->start_html;
                print $q->p("$error");
            }
        }
        else{
            print $q->start_html;
            print $q->p("Bad username/password");

        }
    }
    $ldap_msg = $ldap->unbind;
}
elsif($q->param('action') eq 'logout'){
    $session = CGI::Session->load(undef,undef,{Directory=>$cfg->param("session.dir")}) or die CGI::Session->errstr;
    $session->delete();
    print $session->header(-location=>"index.cgi");
}
else{
    print $q->redirect("./index.cgi");
    print $q->start_html(-title=>'Necto Control');
    print $q->p("No business here, redirecting you");
}
print $q->end_html;

