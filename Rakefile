task :default => [:src]

VER="0.1"

srcball = "ruby-ldapserver-#{VER}.tgz"
sourcefiles = ["README","COPYING","ChangeLog","examples/README"] + Dir["**/*.rb"]

task :src do
  tmpdir = "ruby-ldapserver-#{VER}"
  rm tmpdir if File.exist?(tmpdir)
  File.symlink(".", tmpdir)
  
  srcs = sourcefiles.collect { |f| tmpdir+"/"+f }
  rm(srcball) if File.exist?(srcball)
  sh "tar", "-czf", srcball, *srcs
  rm tmpdir
end

  