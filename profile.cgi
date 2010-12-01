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

# change this if you want to allow different sets of characters for passwords
my $password_policy = '^.*(?=.{'.$cfg->param('user.pwdminlength').','.$cfg->param('user.pwdmaxlength').'})(?=.*\d)(?=.*[a-zA-Z])(?=.*[-!#$%&*+,.:;<=>?@_{|}~]).*$';

# create main cgi object
my $q = CGI->new;
print $q->header(-cache_control=>"no-cache, no-store, must-revalidate");
print $q->start_html(-title=>"Necto Control");
print $q->h1("Necto Control Center");

my $session = CGI::Session->load(undef,undef,{Directory=>$cfg->param("session.dir")});

if ($session->is_expired || $session->is_empty) {
    print $q->redirect("./index.cgi");
    print $q->end_html;
    exit 0;
}

# verify supplied passwords and change it in the LDAP server
if(defined($q->param('newpwd')) && defined($q->param('confpwd'))){

    my $new_password = $q->param('newpwd');
    my $confirmed_password = $q->param('confpwd');

    if($new_password ne $confirmed_password){
        print $q->p("ERROR: passwords are not equals",$q->br);
    }
    elsif($new_password !~ /$password_policy/){
        print $q->p("ERROR: password doesn't respect the policy",$q->br,"$password_policy",$q->br);
    }
    else{
        # all if well, change the password in the directory
        my $ldap = Net::LDAP->new($cfg->param("ldap.address"), port=>$cfg->param("ldap.port"));
        my $ldap_msg = $ldap->bind($session->param('dn'),password=>$session->param('password'));
        unless ($ldap_msg->is_error){

            # change password in LDAP directory
            $ldap_msg = $ldap->modify($session->param('dn'),
                                replace => { 'userPassword' => "$new_password" }
                                );

            if($ldap_msg->is_error){
                print $q->p("Error while changing password",$q->br,$ldap_msg);
            }
            else{
                # change password in session parameters
                $session->param(-name=>'password',-value=>$new_password);
                print $q->p("Password has been changed successfully",$q->br);
            }
        }
    }
}

print $q->h2("Profile Management");
print $q->p("Name: ".$session->param('cn')." ".$session->param('sn'),$q->br,
            "User ID: ".$session->param('uid'),$q->br,
            "Email: ".$session->param('mail'),$q->br
        );
print $q->h3("change your password :");
print $q->p("note: your password must be from ".$cfg->param("user.pwdminlength")." to ".$cfg->param("user.pwdmaxlength")." characters long.",$q->br,"It must contain at least one number (0 to 9), one alphanumerical (a-z or A-Z) and one special character (\-\!\#\$\%\&\*\+\,\.\:\;\<\=\>\?\@\_\{\|\}\~)",$q->br);
print $q->start_form(-method=>"post", -action=>"./profile.cgi");
print $q->p("New password :"),$q->password_field(-name=>"newpwd",-type=>"password");
print $q->p("Confirm password :"),$q->password_field(-name=>"confpwd",-type=>"password");
print $q->submit(-name=>"Submit");


print $q->end_html;
