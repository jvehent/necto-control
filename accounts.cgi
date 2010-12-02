#! /usr/bin/perl -w
use strict;
use CGI;
use CGI::Session ( '-ip_match' );
use CGI::Carp qw/fatalsToBrowser warningsToBrowser/;
use Net::LDAP qw/LDAP_SUCCESS LDAP_PROTOCOL_ERROR/;
use Config::Simple;
use Tie::File;
use String::MkPasswd qw(mkpasswd);
use IMAP::Admin;

# import configuration
my $cfg = new Config::Simple();
$cfg->read('./config/necto.cfg');

# create main cgi object
my $q = CGI->new;

# check session state before initiating html document
my $session = CGI::Session->load(undef,undef,{Directory=>$cfg->param("session.dir")});

if ($session->is_expired || $session->is_empty) {
    print $q->redirect("./index.cgi");
    print $q->start_html(-title=>"Necto Control");
    print $q->end_html;
}

print $q->header(-cache_control=>"no-cache, no-store, must-revalidate");
print $q->start_html(-title=>"Necto Control");
print $q->h1("Necto Control Center");
print $q->h2("Account Management");

# Called with creation arguments, create the user
if( defined($q->param('create_username')) && 
    defined($q->param('create_first_name')) &&
    defined($q->param('create_last_name')) &&
    defined($q->param('ldap_pwd')) )
{

    my $creation_status = 0;

    # generate a random password
    my $create_password = mkpasswd(-length => 10, -minnum => 4, -minlower => 3, -minupper => 2, -minspecial => 1, -distribute => 1);

    # connect to the directory
    my $ldap = Net::LDAP->new($cfg->param("ldap.address"), port=>$cfg->param("ldap.port"));
    my $ldap_msg = $ldap->bind($cfg->param("ldap.admindn"),password=>$q->param('ldap_pwd'));
    unless ($ldap_msg->is_error){

        # search if the username already exist
        $ldap_msg = $ldap->search( filter=>"(uid=".$q->param('create_username').")", base=>$cfg->param("ldap.base"), scope=>$cfg->param("ldap.scope"));

        if($ldap_msg->count != 0){
            print $q->p(" LDAP Error: This entry already exists !",$q->br);
        }
        elsif($ldap_msg->is_error){
            print $q->p(" LDAP Error:",$q->br,$ldap_msg->error);
        }
        else {
            my $create_cn = "cn=".$q->param('create_first_name')." ".$q->param('create_last_name').",".$cfg->param('ldap.base');
            $ldap_msg = $ldap->add($create_cn,
                    attrs => [
                        cn  =>  $q->param('create_first_name')." ".$q->param('create_last_name'),
                        sn  =>  $q->param('create_last_name'),
                        uid =>  $q->param('create_username'),
                        mail=>  $q->param('create_username').'@'.$cfg->param('domain'),
                        userPassword    =>  $create_password,
                        objectClass =>  ['inetOrgPerson', 'top']
                    ]
                );

            if($ldap_msg->is_error){
               print $q->p("LDAP Error: cannot add user",$q->br,$ldap_msg->error);
            }
            else{
                print $q->p("Added user ".$q->param('create_first_name')." ".$q->param('create_last_name')." (login: ".$q->param('create_username').") with email ".$q->param('create_username').'@'.$cfg->param('domain')." and password ".$create_password,$q->br);
                $creation_status = 1;
            }
        }
    }
    else{
        print $q->p("LDAP connection error",$q->br,$ldap_msg->error);
    }
    $ldap_msg = $ldap->unbind;


    # if dspam.pwdfile is defined, add the password for dspam
    if(defined($cfg->param('dspam.pwdfile')) && ($creation_status == 1)){
        tie my @dspam_pwd_array, 'Tie::File', $cfg->param('dspam.pwdfile') or die;

        # search for user and update the line when found
        my $dspam_user;
        if($cfg->param('dspam.userformat') eq 'mail'){
            $dspam_user = $q->param('create_username').'@'.$cfg->param('domain');
        }
        else{
            $dspam_user = $q->param('create_username');
        }
        my $found = 0;
        for my $line (@dspam_pwd_array){
            if($line =~ /^$dspam_user/){
                # found it ! update the line with new password
                $line = $dspam_user.":".crypt($create_password,$create_password);
                $found = 1;
                print $q->p("Dspam access updated for $dspam_user with password $create_password",$q->br);
            }
        }
        if($found == 0){
            # password wasn't found in file, add it
            push @dspam_pwd_array, $dspam_user.":".crypt($create_password,$create_password);
            print $q->p("Dspam access created for $dspam_user with password $create_password",$q->br);
        }
        untie @dspam_pwd_array;
    }

    # connect to cyrus and create the mailbox
    if($creation_status == 1){
        my $imap = IMAP::Admin->new('Server' => $cfg->param('cyrus.address'),
                                    'Login' => $cfg->param('cyrus.admin'),
                                    'Password' => $cfg->param('cyrus.passwd'),
                                    'Port' => $cfg->param('cyrus.port'));

        my $user_mailbox = "user.".$q->param('create_username');
        my $imap_msg = $imap->create($user_mailbox);
        if ($imap_msg != 0) {
            print $q->p("Error while creating mailbox in Cyrus-Imap: $imap->{'Error'}",$q->br);
        }
        else{
            print $q->p("Mailbox created for $user_mailbox",$q->br);
        }
        $imap->close;
    }
}


print $q->h3("Create an account");

print $q->p("The email address will be of the form username@".$cfg->param('domain'),$q->br,'Password is generated automatically',$q->br);
print $q->start_form(-method=>"post", -action=>"./accounts.cgi");
print $q->p("Username :"), $q->textfield(-name=>"create_username",-type=>"text");
print $q->p("First name :"), $q->textfield(-name=>"create_first_name",-type=>"text", -size=>20);
print $q->p("Last name :"), $q->textfield(-name=>"create_last_name",-type=>"text", -size=>20);
print $q->p("To create a user, you need to supply the LDAP directory admin password in the field below",$q->br);
print $q->p("LDAP password :"),$q->password_field(-name=>"ldap_pwd",-type=>"password", -size=>20);
print $q->submit(-name=>"Create user");

print $q->end_form;

print $q->end_html;
