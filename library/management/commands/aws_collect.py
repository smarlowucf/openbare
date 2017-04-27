#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2017 SUSE LLC.
#
# This file is part of openbare.
#
# openbare is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# openbare is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with openbare. If not, see <http://www.gnu.org/licenses/>.

import boto3
import json
import logging

from collections import defaultdict
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils.timezone import UTC
from library.models import Lendable, ManagementCommand, Resource

EVENT_TRIGGERS = [
    'CreateVolume',
    'RunInstances',
    'CreateImage',
    'CreateSnapshot'
]
MODULE_NAME = __name__.split('.')[-1]


def get_available_regions(service, session):
    """List available regions for service."""
    return session.get_available_regions(service)


class Command(BaseCommand):
    help = 'Collect all created resources for EC2 lendables.'
    logger = logging.getLogger(MODULE_NAME)

    def add_arguments(self, parser):
        parser.add_argument(
            '--profile',
            dest='profile',
            default='default',
            help='Boto3 profile to use.'
        )

    def handle(self, *args, **options):
        # determine current run time and previous run time
        run_time = datetime.now(UTC())
        last_run_time = ManagementCommand.get_last_run_time(MODULE_NAME)
        if not last_run_time:
            last_run_time = run_time - timedelta(days=7)

        self.logger.debug('Collecting AWS resources')
        collected = defaultdict(list)
        session = boto3.Session(profile_name=options['profile'])
        for region in get_available_regions('cloudtrail', session):
            # Check all available cloudtrail regions for events
            MAX_RESULTS = 50
            cloud_trail = session.client('cloudtrail', region_name=region)

            results_left = True
            token = None
            while results_left:
                # If results greater than 50 there will be pages
                # loop through each page until no next token.
                if token:
                    events = cloud_trail.lookup_events(
                        StartTime=last_run_time,
                        MaxResults=MAX_RESULTS,
                        NextToken=token
                    )
                else:
                    events = cloud_trail.lookup_events(
                        StartTime=last_run_time,
                        MaxResults=MAX_RESULTS
                    )

                if 'NextToken' in events:
                    token = events['NextToken']
                else:
                    token = None
                    results_left = False

                for event in events['Events']:
                    if event['EventName'] in EVENT_TRIGGERS:
                        # If the event is in triggers list log it.
                        event_name = event['EventName']
                        detail = json.loads(event['CloudTrailEvent'])

                        region = detail['awsRegion']
                        principal = detail['userIdentity']['principalId']
                        user_type = detail['userIdentity']['type']

                        if user_type == 'Root':
                            user = principal

                        elif user_type == 'IAMUser':
                            user = detail['userIdentity']['userName']

                        else:
                            user = principal.split(':')[-1]

                        resource = {
                            'region': region,
                            'user': user,
                            'userType': user_type,
                            'principal': principal
                        }

                        if event_name == 'RunInstances':
                            items = (
                                detail['responseElements']
                                ['instancesSet']
                                ['items']
                            )
                            for item in items:
                                instance = dict(resource)
                                instance['id'] = item['instanceId']
                                instance['type'] = 'instance'
                                collected[user].append(instance)

                        else:
                            if event_name == 'CreateVolume':
                                resource['id'] = (
                                    detail['responseElements']['volumeId']
                                )
                                resource['type'] = 'vol'

                            elif event_name == 'CreateImage':
                                resource['id'] = (
                                    detail['responseElements']['imageId']
                                )
                                resource['type'] = 'image'

                            elif event_name == 'CreateSnapshot':
                                resource['id'] = (
                                    detail['responseElements']['snapshotId']
                                )
                                resource['type'] = 'snapshot'

                            collected[user].append(resource)

        lendable_resources = []
        for username, resources in collected.items():
            # Create list of resource objects
            try:
                lendable = Lendable.all_types.get(username=username)
            except:
                lendable = None

            for resource in resources:
                lendable_resources.append(
                    Resource(
                        lendable=lendable,
                        region=resource['region'],
                        resource_type=resource['type'],
                        resource_id=resource['id']
                    )
                )

        # Bulk create all new resources
        Resource.objects.bulk_create(lendable_resources)
        message = 'Logged %i resource(s)' % len(lendable_resources)
        self.stdout.write(self.style.SUCCESS(message))
        self.logger.debug(message)

        # update last run time for command
        ManagementCommand.update_last_run_time(MODULE_NAME, run_time)
