use inc::Module::Install;

RTx     'RT-Extension-SpamFilter';
license 'gplv2';
repository 'https://github.com/bestpractical/rt-extension-spamfilter';

requires_rt_plugin 'RT::Extension::FutureMailgate';

requires_rt '4.0.0';
rt_too_new '4.4.0';

sign;
WriteAll;
