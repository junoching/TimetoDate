-- 一群人約時間（GitHub 共用版）— Supabase 後端設定
-- 用法：在 Supabase 專案的 SQL Editor 整段貼上，按 Run，一次完成。
-- 設計：events 表只存公開資料（不含 PIN）；PIN 雜湊獨立存 event_secrets，
-- 且 anon 角色對 event_secrets 沒有任何權限，只能透過下列兩個
-- security definer 函數設定／驗證，PIN 不會出現在任何 API 回應中。

create extension if not exists pgcrypto;

create table public.events (
  id text primary key,                       -- 短代號，例如 k7x2ab
  title text not null,
  start_date date not null,
  end_date date not null,
  day_start time not null,                   -- 每日時段開始，例如 14:00
  day_end time not null,                     -- 每日時段結束，例如 22:00
  created_at timestamptz not null default now(),
  constraint period_order check (end_date >= start_date),
  constraint period_max_31 check (end_date - start_date <= 30)
);

create table public.event_secrets (
  event_id text primary key references public.events(id) on delete cascade,
  pin_hash text not null
);

create table public.responses (
  id uuid primary key default gen_random_uuid(),
  event_id text not null references public.events(id) on delete cascade,
  name text not null,
  slots jsonb not null default '[]'::jsonb,  -- ["2026-12-05T19:00", ...] 每格 30 分鐘
  updated_at timestamptz not null default now(),
  unique (event_id, name)
);

alter table public.events enable row level security;
alter table public.event_secrets enable row level security;
alter table public.responses enable row level security;

-- 新版 Supabase 專案不會自動授權給 anon 角色，必須顯式 GRANT（RLS policy 再在此之上過濾）
grant select on public.events to anon;
grant select, insert, update, delete on public.responses to anon;
-- event_secrets 不授權：anon 完全不能碰

-- events：任何人可讀公開資料；新增只能經 create_event 函數（連 PIN 一次過寫入）
create policy "events read" on public.events
  for select to anon using (true);

-- event_secrets：不設任何 anon policy，即 anon 不能讀寫，只有函數可碰

-- responses：任何人可讀、可新增、可更新、可刪除自己的回覆
-- （朋友之間互信模式，與私人原型一致；同名再入即載入自己嗰份修改）
create policy "responses read" on public.responses
  for select to anon using (true);
create policy "responses insert" on public.responses
  for insert to anon with check (true);
create policy "responses update" on public.responses
  for update to anon using (true) with check (true);
create policy "responses delete" on public.responses
  for delete to anon using (true);

-- 建立活動：驗證 PIN 格式（4–6 位數字）與 period 上限，原子寫入活動＋PIN 雜湊
create or replace function public.create_event(
  p_id text, p_title text,
  p_start date, p_end date,
  p_day_start time, p_day_end time,
  p_pin text
) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if p_pin is null or p_pin !~ '^[0-9]{4,6}$' then return false; end if;
  if p_end < p_start or p_end - p_start > 30 then return false; end if;
  if p_day_end <= p_day_start then return false; end if;
  insert into public.events(id, title, start_date, end_date, day_start, day_end)
  values (p_id, p_title, p_start, p_end, p_day_start, p_day_end);
  insert into public.event_secrets(event_id, pin_hash)
  values (p_id, extensions.crypt(p_pin, extensions.gen_salt('bf')));
  return true;
end $$;

-- 刪除活動：驗證 PIN 後成個活動連回覆一併刪除（cascade）
-- 沒有 PIN 紀錄的活動（理論上不會出現）視為免 PIN 可刪
create or replace function public.delete_event(p_event_id text, p_pin text)
returns boolean
language plpgsql security definer set search_path = public as $$
declare h text;
begin
  select pin_hash into h from public.event_secrets where event_id = p_event_id;
  if h is not null and extensions.crypt(coalesce(p_pin, ''), h) <> h then
    return false;
  end if;
  delete from public.events where id = p_event_id;
  return found;
end $$;

grant execute on function public.create_event(text, text, date, date, time, time, text) to anon;
grant execute on function public.delete_event(text, text) to anon;
