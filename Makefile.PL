use inc::Module::Install;

RTx     'RT-Extension-SpamFilter';
license 'gplv2';
repository 'https://github.com/bestpractical/rt-extension-spamfilter';

if ( $RT::VERSION =~ /^4\.2/ ) {
    requires_rt_plugin 'RT::Extension::FutureMailgate';
}

requires_rt '4.0.0';
rt_too_new '5.2.0';

sign;
WriteAll;
