(function(){
var DARK=document.documentElement.getAttribute('data-theme')==='dark',ACC=DARK?'#38BDF8':'#7C3AED',ACC2=DARK?'#22C55E':'#C4B5FD',RGB=DARK?'56,189,248':'124,58,237',CARD=DARK?'#172033':'#fff';
var PAL=DARK?['#38BDF8','#0EA5E9','#7DD3FC','#818CF8','#22D3EE','#2DD4BF','#A78BFA','#60A5FA','#34D399','#BAE6FD','#0284C7']:['#7C3AED','#8B5CF6','#A78BFA','#C4B5FD','#6D28D9','#5B21B6','#9333EA','#C026D3','#DB2777','#DDD6FE','#4C1D95'];
var SEVC={Critical:'#DC2626',High:'#F97316',Medium:'#F59E0B',Low:'#8B5CF6'};
var STC={Open:'#DC2626',Acknowledged:'#F59E0B','In Progress':'#6366F1',Resolved:'#16A34A',Closed:'#94A3B8'};
var KP=[['k_total','Total alerts','fa-bell','acc'],['k_crit','Critical alerts','fa-fire','bad'],['k_open','Open incidents','fa-folder-open','warn'],['k_res','Resolved incidents','fa-circle-check','ok'],
 ['k_br','SLA-breached','fa-stopwatch','bad'],['k_ack','Avg acknowledgement','fa-bolt','acc'],['k_rt','Avg resolution','fa-hourglass-half','acc'],['k_an','Active analysts','fa-user-shield','ok']];
var charts={},prev=null,lastKey=null,GRID=DARK?'#26334d':'#EFEAFB';
if(window.Chart){Chart.defaults.font.family="'Plus Jakarta Sans','Segoe UI',sans-serif";Chart.defaults.color=DARK?'#94A3B8':'#6B6880';Chart.defaults.animation={duration:900,easing:'easeOutQuart'};}
function $(i){return document.getElementById(i)}
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':s;return d.innerHTML}
function fm(m){return m==null?'—':(m<60?m.toFixed(1)+' min':(m/60).toFixed(1)+' h')}
function pill(v){return '<span class="pill s-'+esc(v).replace(/[ \/]/g,'')+'">'+esc(v)+'</span>'}
function tween(el,a,b){var t0=performance.now();(function f(t){var p=Math.min(1,(t-t0)/800),e=1-Math.pow(1-p,3);el.textContent=Math.round(a+(b-a)*e);if(p<1)requestAnimationFrame(f)})(t0)}
function setKpi(id,v){var el=$(id);if(!el)return;if(typeof v==='number'){var from=+el.dataset.v||0;el.dataset.v=v;tween(el,from,v)}else if(el.textContent!==v){el.textContent=v;el.classList.remove('pop');void el.offsetWidth;el.classList.add('pop')}}
function draw(id,cfg){var c=charts[id];if(c){c.data=cfg.data;c.update()}else charts[id]=new Chart($(id),cfg)}
var base={responsive:true,maintainAspectRatio:false},sc={x:{grid:{display:false}},y:{grid:{color:GRID},beginAtZero:true}};
function buildKpis(){$('kpis').innerHTML=KP.map(function(k,i){return '<div class="col-6 col-lg-3"><div class="cardx kpi '+k[3]+'" style="--i:'+i+'"><div class="ic"><i class="fa-solid '+k[2]+'"></i></div><div><div class="l">'+k[1]+'</div><div class="v" id="'+k[0]+'">0</div></div></div></div>'}).join('')}
function render(d,q){
 var s=d.summary;
 setKpi('k_total',s.total);setKpi('k_crit',s.critical);setKpi('k_open',s.open);setKpi('k_res',s.resolved);setKpi('k_br',s.breached);setKpi('k_ack',fm(s.avg_ack));setKpi('k_rt',fm(s.avg_res));setKpi('k_an',s.active_analysts);
 if(lastKey!==q){prev=null;lastKey=q}
 if(prev!==null&&s.total>prev)window.toast((s.total-prev)+' new alert(s) detected and classified','success');
 prev=s.total;
 var origin=$('origin').value,types=Object.keys(s.category).filter(function(k){return s.category[k]>0}).sort(function(a,b){return s.category[b]-s.category[a]});
 $('types').innerHTML=types.length?types.map(function(t,i){return '<a class="chip" style="animation-delay:'+i*50+'ms" href="/alerts?category='+encodeURIComponent(t)+(origin?'&origin='+origin:'')+'">'+esc(t)+' <b>'+s.category[t]+'</b></a>'}).join(''):'<span class="note">No alerts match the current filters.</span>';
 var sk=Object.keys(s.severity),tk=Object.keys(s.status);
 draw('c_sev',{type:'doughnut',data:{labels:sk,datasets:[{data:sk.map(function(x){return s.severity[x]}),backgroundColor:sk.map(function(x){return SEVC[x]}),borderWidth:3,borderColor:CARD,hoverOffset:10}]},options:Object.assign({cutout:'62%'},base)});
 draw('c_stat',{type:'doughnut',data:{labels:tk,datasets:[{data:tk.map(function(x){return s.status[x]}),backgroundColor:tk.map(function(x){return STC[x]}),borderWidth:3,borderColor:CARD,hoverOffset:10}]},options:Object.assign({cutout:'62%'},base)});
 draw('c_trend',{type:'line',data:{labels:d.trend.map(function(t){return t[0].slice(5)}),datasets:[{label:'Alerts',data:d.trend.map(function(t){return t[1]}),borderColor:ACC,borderWidth:3,tension:.4,fill:true,pointRadius:2,pointBackgroundColor:ACC,
  backgroundColor:function(c){var a=c.chart.chartArea;if(!a)return 'rgba('+RGB+',.15)';var g=c.chart.ctx.createLinearGradient(0,a.top,0,a.bottom);g.addColorStop(0,'rgba('+RGB+',.35)');g.addColorStop(1,'rgba('+RGB+',0)');return g}}]},options:Object.assign({scales:sc,plugins:{legend:{display:false}}},base)});
 draw('c_cat',{type:'bar',data:{labels:types,datasets:[{label:'Alerts',data:types.map(function(x){return s.category[x]}),backgroundColor:types.map(function(x,i){return PAL[i%PAL.length]}),borderRadius:8}]},options:Object.assign({indexAxis:'y',scales:{x:{grid:{color:GRID},beginAtZero:true},y:{grid:{display:false}}},plugins:{legend:{display:false}}},base)});
 var a=d.analysts,nm=a.map(function(x){return x.name});
 draw('c_work',{type:'bar',data:{labels:nm,datasets:[{label:'Assigned',data:a.map(function(x){return x.total}),backgroundColor:ACC,borderRadius:8},{label:'Open',data:a.map(function(x){return x.open}),backgroundColor:'#F59E0B',borderRadius:8}]},options:Object.assign({scales:sc},base)});
 draw('c_resp',{type:'bar',data:{labels:nm,datasets:[{label:'Avg acknowledgement (min)',data:a.map(function(x){return x.avg_ack}),backgroundColor:ACC,borderRadius:8},{label:'Avg resolution (min)',data:a.map(function(x){return x.avg_res}),backgroundColor:ACC2,borderRadius:8}]},options:Object.assign({scales:sc},base)});
 $('recent').innerHTML=d.recent.length?d.recent.map(function(r,i){return '<tr style="animation-delay:'+i*40+'ms" class="'+(r.severity==='Critical'&&r.status!=='Resolved'&&r.status!=='Closed'?'crit':'')+'"><td>'+esc(r.alert_code)+'<div class="note">'+(r.origin==='demo'?'DEMO':esc(r.origin).toUpperCase())+'</div></td><td>'+esc(r.title)+'</td><td>'+pill(r.severity)+'</td><td>'+pill(r.status)+'</td><td>'+pill(r.sla)+'</td><td>'+esc(r.analyst_name||'Unassigned')+'</td><td>'+esc(r.created_at.replace('T',' '))+'</td><td><a href="/incident/'+r.id+'">View</a></td></tr>'}).join(''):'<tr><td colspan="8" class="note">No incidents match the selected filters.</td></tr>';
}
async function load(silent){
 if(!silent)$('state').innerHTML='<span class="skeleton-line"></span>';
 var q='days='+$('days').value+'&severity='+encodeURIComponent($('sev').value)+'&origin='+encodeURIComponent($('origin').value);
 try{
  if(typeof Chart==='undefined')throw new Error('Chart.js could not load (internet access needed for CDN).');
  var r=await fetch('/api/dashboard?'+q);if(!r.ok)throw new Error('Server returned '+r.status);
  render(await r.json(),q);$('state').textContent='';$('updated').textContent='Updated '+new Date().toLocaleTimeString();$('dot').className='dot';$('live-text').textContent='Live';
 }catch(e){$('state').textContent='';$('dot').className='dot off';$('live-text').textContent='Offline';if(!silent)window.toast('Failed to load analytics: '+e.message,'danger')}
}
var p=new URLSearchParams(location.search);if(p.get('origin'))$('origin').value=p.get('origin');
buildKpis();
['days','sev','origin'].forEach(function(i){$(i).addEventListener('change',function(){load(false)})});
$('refresh').addEventListener('click',function(){load(false)});
setInterval(function(){if($('live').checked&&!document.hidden)load(true)},15000);
load(false);
})();
